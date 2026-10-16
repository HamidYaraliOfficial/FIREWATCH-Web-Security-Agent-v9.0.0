from __future__ import annotations

import asyncio
import hmac
import io
import json
import logging
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .check_catalog import CATALOG, coverage_matrix
from .assessment_catalog import get_assessment_plan
from .config import settings, validate_settings
from .db import SessionLocal, get_db, init_db
from .models import (
    Asset, Evidence, Finding, FindingStatus, Page, Report, Scan, ScanEvent,
    ScanStatus, Severity,
)
from .orchestrator import ScanOrchestrator
from .redaction import contains_sensitive_query, redact_data
from .schemas import AssetOut, EventOut, FindingOut, ScanCreate, ScanDetail, ScanSummary
from .scope import ScopePolicy, ScopeViolation
from .secret_store import protect_config, public_config
from .version import VERSION
from .bundle_manifest import build_report_manifest

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
logger = logging.getLogger("firewatch.api")
HERE = Path(__file__).resolve()
ROOT = HERE.parents[2] if (HERE.parents[2] / "frontend").exists() else HERE.parents[1]
FRONTEND = ROOT / "frontend"
REPORT_FORMATS = {
    "html": ("text/html", ".html"),
    "json": ("application/json", ".json"),
    "csv": ("text/csv; charset=utf-8", ".csv"),
    "markdown": ("text/markdown; charset=utf-8", ".md"),
    "sarif": ("application/sarif+json", ".sarif.json"),
}


async def queue_loop(stop_event: asyncio.Event):
    """Single-process development queue. Production multi-worker deployments should
    run the documented external worker topology instead of multiplying API loops.
    """
    while not stop_event.is_set():
        db = SessionLocal()
        try:
            scan = db.scalar(
                select(Scan).where(Scan.status == ScanStatus.QUEUED)
                .order_by(Scan.created_at.asc())
                .with_for_update(skip_locked=True).limit(1)
            )
            if scan:
                scan.status = ScanStatus.RUNNING
                db.commit()
                try:
                    await ScanOrchestrator(db).run(scan)
                except Exception:
                    logger.exception("queued scan failed: %s", scan.id)
            else:
                await asyncio.sleep(0.75)
        finally:
            db.close()


@asynccontextmanager
async def lifespan(_app):
    config_errors = validate_settings(settings)
    if config_errors:
        # Only setting names/ranges are reported; never echo key or credential values.
        raise RuntimeError("Invalid FIREWATCH configuration: " + "; ".join(config_errors))
    init_db()
    stop = asyncio.Event()
    # One in-process worker is appropriate for local/dev use only.
    # Disable it when running the separate `app.worker` process in production.
    task = asyncio.create_task(queue_loop(stop)) if getattr(settings, "enable_inline_worker", True) else None
    try:
        yield
    finally:
        stop.set()
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


app = FastAPI(title=settings.app_name, version=VERSION, docs_url="/docs", redoc_url="/redoc", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


@app.middleware("http")
async def baseline_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path == "/":
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
    return response


def require_api_key(x_api_key: str | None = Header(default=None)):
    configured = settings.api_key
    if not configured and settings.environment.lower() in {"production", "prod"}:
        raise HTTPException(503, "FIREWATCH_API_KEY must be configured in production")
    if configured and (not x_api_key or not hmac.compare_digest(x_api_key, configured)):
        raise HTTPException(401, "Valid X-API-Key header required")


def _get_scan_or_404(scan_id: str, db: Session) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


@app.get("/health")
def health():
    return {
        "status": "ok", "service": "firewatch-api", "version": VERSION,
        "scanner": "scope-controlled",
        "api_key_protection": bool(settings.api_key or settings.environment.lower() in {"production", "prod"}),
    }


@app.get("/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(select(1)).scalar_one()
    except Exception as exc:
        logger.warning("readiness check failed: %s", type(exc).__name__)
        raise HTTPException(503, "Database is not ready") from exc
    return {"status": "ready", "database": "reachable"}


@app.get("/api/v1/coverage", dependencies=[Depends(require_api_key)])
def coverage():
    return {
        "baseline": ["OWASP Top 10:2025", "OWASP WSTG stable (v4.2)", "OWASP ASVS 5.0.0", "OWASP API Security Top 10:2023"],
        "catalog": CATALOG,
        "note": "Coverage is mapped at category/rule-family level. No finding is not proof of absence.",
    }


@app.get("/api/v1/assessment-plan", dependencies=[Depends(require_api_key)])
def assessment_plan():
    """Return the full test plan, explicitly separating automated checks from manual work."""
    return get_assessment_plan()


@app.post("/api/v1/scans", response_model=ScanSummary, status_code=201, dependencies=[Depends(require_api_key)])
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)):
    if settings.require_scope_ack and not payload.scope_acknowledged:
        raise HTTPException(400, "scope_acknowledged must be true for an active security assessment")
    target = str(payload.target_url)
    if contains_sensitive_query(target):
        raise HTTPException(400, "Do not place credentials/tokens in the target URL; use encrypted authentication fields")
    try:
        # from_root performs URL validation, port-aware scope creation and private-IP checks.
        policy = ScopePolicy.from_root(
            target, exclusions=payload.exclusions,
            allow_private_targets=settings.allow_private_targets,
            allowed_hosts=payload.allowed_hosts,
        )
        target = policy.validate_url(target)
    except ScopeViolation as exc:
        raise HTTPException(400, str(exc)) from exc
    cfg = payload.model_dump(exclude={"target_url", "project_id", "scope_acknowledged"})
    try:
        cfg = protect_config(cfg)
    except Exception as exc:
        logger.exception("could not protect scan credentials")
        raise HTTPException(500, f"Could not safely encrypt scan credentials: {type(exc).__name__}") from exc
    scan = Scan(project_id=payload.project_id, target_url=target, config=cfg)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@app.get("/api/v1/scans", response_model=list[ScanSummary], dependencies=[Depends(require_api_key)])
def list_scans(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(limit)))


@app.get("/api/v1/scans/{scan_id}", response_model=ScanDetail, dependencies=[Depends(require_api_key)])
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(scan_id, db)
    counts = {
        "pages_count": db.scalar(select(func.count()).select_from(Page).where(Page.scan_id == scan.id)) or 0,
        "assets_count": db.scalar(select(func.count()).select_from(Asset).where(Asset.scan_id == scan.id)) or 0,
        "findings_count": db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)) or 0,
        "events_count": db.scalar(select(func.count()).select_from(ScanEvent).where(ScanEvent.scan_id == scan.id)) or 0,
    }
    data = {column.name: getattr(scan, column.name) for column in Scan.__table__.columns}
    data["config"] = public_config(scan.config)
    data.update(counts)
    return ScanDetail.model_validate(data)


@app.get("/api/v1/scans/{scan_id}/findings", response_model=list[FindingOut], dependencies=[Depends(require_api_key)])
def list_findings(
    scan_id: str,
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    category: str | None = Query(default=None, max_length=100),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    _get_scan_or_404(scan_id, db)
    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if status is not None:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)
    return list(db.scalars(query.order_by(Finding.risk_score.desc()).offset(offset).limit(limit)))


@app.get("/api/v1/scans/{scan_id}/events", response_model=list[EventOut], dependencies=[Depends(require_api_key)])
def list_events(scan_id: str, limit: int = Query(500, ge=1, le=2000), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    _get_scan_or_404(scan_id, db)
    return list(db.scalars(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id)
        .order_by(ScanEvent.created_at.asc()).offset(offset).limit(limit)
    ))


@app.get("/api/v1/scans/{scan_id}/assets", response_model=list[AssetOut], dependencies=[Depends(require_api_key)])
def list_assets(
    scan_id: str,
    kind: str | None = Query(default=None, max_length=60),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    _get_scan_or_404(scan_id, db)
    query = select(Asset).where(Asset.scan_id == scan_id)
    if kind:
        query = query.where(Asset.kind == kind)
    return list(db.scalars(query.order_by(Asset.id).offset(offset).limit(limit)))


@app.get("/api/v1/scans/{scan_id}/evidence", dependencies=[Depends(require_api_key)])
def list_evidence(
    scan_id: str,
    finding_id: str | None = None,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    _get_scan_or_404(scan_id, db)
    query = select(Evidence).join(Finding, Evidence.finding_id == Finding.id).where(Finding.scan_id == scan_id)
    if finding_id:
        query = query.where(Evidence.finding_id == finding_id)
    items = list(db.scalars(query.order_by(Evidence.created_at.asc()).offset(offset).limit(limit)))
    return [{
        "id": item.id,
        "finding_id": item.finding_id,
        "kind": item.kind,
        "data": redact_data(item.data or {}),
        "created_at": item.created_at,
    } for item in items]


@app.get("/api/v1/scans/{scan_id}/coverage", dependencies=[Depends(require_api_key)])
def scan_coverage(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(scan_id, db)
    findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))
    assets = db.scalar(select(func.count()).select_from(Asset).where(Asset.scan_id == scan_id)) or 0
    pages = db.scalar(select(func.count()).select_from(Page).where(Page.scan_id == scan_id)) or 0
    return {
        "scan_id": scan.id,
        "status": scan.status.value,
        "pages_discovered": pages,
        "assets_discovered": assets,
        "findings_recorded": len(findings),
        "catalog": coverage_matrix(findings),
        "interpretation": "finding_observed means at least one mapped rule produced a finding; no_finding_recorded_or_not_applicable is not a clean bill of health.",
    }


@app.post("/api/v1/scans/{scan_id}/cancel", dependencies=[Depends(require_api_key)])
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(scan_id, db)
    if scan.status in {ScanStatus.QUEUED, ScanStatus.RUNNING}:
        # Atomic transition so a concurrent completion cannot be overwritten.
        db.execute(update(Scan).where(
            Scan.id == scan_id,
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
        ).values(status=ScanStatus.CANCELED))
        db.commit()
        db.refresh(scan)
    return {"id": scan.id, "status": scan.status.value, "note": "Cancellation is cooperative; an in-flight request may finish before the worker stops."}


@app.get("/api/v1/scans/{scan_id}/diff", dependencies=[Depends(require_api_key)])
def scan_diff(scan_id: str, db: Session = Depends(get_db)):
    current = _get_scan_or_404(scan_id, db)
    if current.status != ScanStatus.COMPLETED:
        raise HTTPException(409, "Current scan must be completed before diffing")
    previous = db.scalar(
        select(Scan).where(Scan.target_url == current.target_url, Scan.status == ScanStatus.COMPLETED,
                           Scan.created_at < current.created_at)
        .order_by(Scan.created_at.desc()).limit(1)
    )
    if not previous:
        return {"scan_id": current.id, "baseline_scan_id": None, "added": [], "resolved": [], "unchanged": [],
                "message": "No previous completed scan for this exact target URL."}

    def keyed(scan_identifier: str):
        found = list(db.scalars(select(Finding).where(Finding.scan_id == scan_identifier)))
        data = {}
        for finding in found:
            parsed = urlsplit(finding.endpoint)
            key = f"{finding.rule_id}|{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
            data.setdefault(key, {
                "rule_id": finding.rule_id, "title": finding.title, "severity": finding.severity.value,
                "endpoint": finding.endpoint, "status": finding.status.value, "risk_score": finding.risk_score,
            })
        return data

    old = keyed(previous.id)
    new = keyed(current.id)
    return {
        "scan_id": current.id, "baseline_scan_id": previous.id,
        "added": [new[key] for key in sorted(new.keys() - old.keys())],
        "resolved": [old[key] for key in sorted(old.keys() - new.keys())],
        "unchanged": [new[key] for key in sorted(new.keys() & old.keys())],
        "message": "Diff keys use rule ID + endpoint path (query values ignored). Manual review is recommended.",
    }


@app.get("/api/v1/scans/{scan_id}/report", dependencies=[Depends(require_api_key)])
def report(scan_id: str, format: str = "html", db: Session = Depends(get_db)):
    if format not in REPORT_FORMATS:
        raise HTTPException(400, "Supported formats: html, json, csv, markdown, sarif")
    scan = _get_scan_or_404(scan_id, db)
    item = db.scalar(select(Report).where(Report.scan_id == scan.id, Report.format == format))
    if not item or not Path(item.path).is_file():
        raise HTTPException(404, "Report not available yet")
    media_type, _ = REPORT_FORMATS[format]
    return FileResponse(item.path, media_type=media_type, filename=Path(item.path).name, headers={"X-Content-Type-Options": "nosniff"})


@app.get("/api/v1/scans/{scan_id}/bundle", dependencies=[Depends(require_api_key)])
def report_bundle(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(scan_id, db)
    rows = list(db.scalars(select(Report).where(Report.scan_id == scan.id).order_by(Report.format)))
    available = [(row, Path(row.path)) for row in rows if row.format in REPORT_FORMATS and Path(row.path).is_file()]
    if not available:
        raise HTTPException(404, "No reports are available for this scan yet")
    buffer = io.BytesIO()
    report_payloads = []
    for row, path in available:
        _, suffix = REPORT_FORMATS[row.format]
        report_payloads.append((row.format, suffix, path.read_bytes()))
    manifest = build_report_manifest(scan.id, report_payloads)
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for report_format, suffix, content in report_payloads:
            archive.writestr(f"{scan.id}/report{suffix}", content)
        archive.writestr(f"{scan.id}/manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        text_lines = ["FIREWATCH report bundle", f"Application version: {VERSION}", "Hash algorithm: SHA-256"]
        for item in manifest["reports"]:
            text_lines.append(f"{item['format']}: {item['path']} | {item['size_bytes']} bytes | sha256={item['sha256']}")
        text_lines.append("NOTE: The manifest is not digitally signed.")
        archive.writestr(f"{scan.id}/manifest.txt", "\n".join(text_lines) + "\n")
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="firewatch-{scan.id}.zip"', "X-Content-Type-Options": "nosniff"},
    )


@app.get("/", response_class=HTMLResponse)
def ui():
    path = FRONTEND / "index.html"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return '<h1>FIREWATCH Web Security Agent v9</h1><p>API: <a href="/docs">/docs</a></p>'


@app.get("/static/{file_path:path}")
def static(file_path: str):
    path = (FRONTEND / "static" / file_path).resolve()
    try:
        path.relative_to((FRONTEND / "static").resolve())
    except ValueError as exc:
        raise HTTPException(404, "Not found") from exc
    if not path.is_file():
        raise HTTPException(404, "Not found")
    return FileResponse(path, headers={"X-Content-Type-Options": "nosniff"})
