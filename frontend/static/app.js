'use strict';

const $ = (selector) => document.querySelector(selector);
const API = '/api/v1';
let selectedScanId = null;
let scanCache = [];
let pollTimer = null;

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[char]));
}

function prettyDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? esc(value) : esc(date.toLocaleString());
}

async function api(path, options = {}) {
  const key = sessionStorage.getItem('fw_api_key') || '';
  const headers = new Headers(options.headers || {});
  if (key) headers.set('X-API-Key', key);
  const response = await fetch(`${API}${path}`, { ...options, headers });
  const raw = await response.text();
  let data;
  try { data = JSON.parse(raw); } catch { data = raw; }
  if (!response.ok) {
    const detail = data && typeof data === 'object' ? data.detail : data;
    throw new Error(detail || `Request failed (HTTP ${response.status})`);
  }
  return data;
}

async function download(path, filename) {
  const key = sessionStorage.getItem('fw_api_key') || '';
  const response = await fetch(path, { headers: key ? { 'X-API-Key': key } : {} });
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try { const body = await response.json(); message = body.detail || message; } catch { /* keep status */ }
    throw new Error(message);
  }
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 30_000);
}

function parseJsonField(id, label, expected) {
  const value = $(`#${id}`).value.trim();
  if (!value) return expected === 'array' ? [] : {};
  let parsed;
  try { parsed = JSON.parse(value); }
  catch { throw new Error(`${label} must be valid JSON.`); }
  if (expected === 'array' ? !Array.isArray(parsed) : (!parsed || Array.isArray(parsed) || typeof parsed !== 'object')) {
    throw new Error(`${label} must be a JSON ${expected === 'array' ? 'array' : 'object'}.`);
  }
  return parsed;
}

function listField(id) {
  return $(`#${id}`).value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
}

function render() {
  $('#app').innerHTML = `
    <header class="top">
      <div>
        <div class="brand">FIREWATCH <span class="small">v9.0.0</span></div>
        <div class="sub">Evidence-driven Web Security Assessment · Scope-controlled</div>
      </div>
      <div class="row api-key-row">
        <input class="input" id="apiKey" type="password" autocomplete="new-password" placeholder="API key (if configured)" aria-label="API key">
        <button class="btn secondary" id="saveKey" type="button">Use key for this tab</button>
        <button class="btn secondary" id="refresh" type="button">Refresh</button>
        <a class="btn secondary" href="/docs">API Docs</a>
      </div>
    </header>
    <main class="wrap">
      <section class="card">
        <h1>Security Assessment Console</h1>
        <p class="muted">Run an evidence-producing assessment against a target you are explicitly authorized to test. The default engine is non-destructive: it does not brute-force credentials, submit arbitrary forms, perform write/delete operations, or send executable injection payloads.</p>
        <div class="notice"><b>Before starting:</b> confirm written authorization, approved hosts/ports, excluded paths, credentials, request rate, and testing window. Baseline and comprehensive checks have different coverage and limits.</div>
        <form id="scanForm" style="margin-top:14px">
          <label class="small" for="url">Target URL</label>
          <input class="input" id="url" type="url" value="http://127.0.0.1:8765/" required maxlength="2048" autocomplete="url">
          <div class="grid3" style="margin-top:12px">
            <div><label class="small" for="profile">Assessment profile</label><select class="input" id="profile"><option value="baseline">Baseline · passive</option><option value="standard" selected>Standard · recommended</option><option value="comprehensive">Comprehensive · bounded</option></select></div>
            <div><label class="small" for="pages">Max pages</label><input class="input" id="pages" type="number" min="1" max="5000" value="300"></div>
            <div><label class="small" for="depth">Max crawl depth</label><input class="input" id="depth" type="number" min="0" max="20" value="8"></div>
          </div>
          <div class="grid3" style="margin-top:12px">
            <div><label class="small" for="delay">Minimum request delay (ms)</label><input class="input" id="delay" type="number" min="0" max="10000" value="150"></div>
            <label class="checkline"><input type="checkbox" id="browser" checked> Browser discovery</label>
            <label class="checkline"><input type="checkbox" id="gql" checked> Read-only GraphQL introspection</label>
          </div>
          <div class="grid3" style="margin-top:12px">
            <label class="checkline"><input type="checkbox" id="robots" checked> Respect robots.txt</label>
            <label class="checkline"><input type="checkbox" id="parameterProbes" checked> Harmless GET canaries</label>
            <label class="checkline"><input type="checkbox" id="passive"> Passive-only assessment</label>
          </div>
          <details class="advanced" style="margin-top:14px">
            <summary>Scope controls and exclusions</summary>
            <div class="grid3" style="margin-top:12px">
              <div><label class="small" for="allowedHosts">Additional in-scope hosts (one per line)</label><textarea class="input" id="allowedHosts" rows="3" placeholder="https://api.example.com"></textarea><div class="small">Only add hosts explicitly approved for this assessment.</div></div>
              <div><label class="small" for="exclusions">Excluded paths (one per line)</label><textarea class="input" id="exclusions" rows="3" placeholder="/logout&#10;/payment&#10;/delete-account"></textarea><div class="small">Excluded paths are never crawled or requested.</div></div>
              <div class="scope-note"><b>Scope enforcement</b><p class="small">Out-of-scope hosts/ports are blocked. Redirects are not automatically followed by the HTTP engine. Sensitive query-string URLs are excluded.</p></div>
            </div>
          </details>
          <details class="advanced" style="margin-top:10px">
            <summary>Authentication and authorization profiles (optional)</summary>
            <p class="small">Credentials are encrypted in the database. Primary headers/cookies are only attached to the exact root hostname, root scheme, and HTTPS for public targets. They are not saved by this page to local storage. Use dedicated, low-privilege test identities.</p>
            <div class="grid3" style="margin-top:12px">
              <div><label class="small" for="requestHeaders">Primary request headers (JSON object)</label><textarea class="input secret-input" id="requestHeaders" rows="5" spellcheck="false" autocomplete="off" placeholder='{"Authorization":"Bearer YOUR_TEST_TOKEN"}'></textarea><div class="small">Example header values are placeholders; do not paste production tokens.</div></div>
              <div><label class="small" for="authCookies">Cookie header (optional)</label><input class="input secret-input" id="authCookies" type="password" autocomplete="new-password" placeholder="session=TEST_SESSION"><div class="small">Sent only to the root host under the credential policy.</div></div>
              <div><label class="small" for="authProfiles">Role comparison profiles (JSON array)</label><textarea class="input secret-input" id="authProfiles" rows="5" spellcheck="false" autocomplete="off" placeholder='[{"name":"admin","headers":{"Authorization":"Bearer ADMIN_TEST_TOKEN"}},{"name":"user","headers":{"Authorization":"Bearer USER_TEST_TOKEN"}}]'></textarea><div class="small">Only read-only GET comparisons are used; findings are review candidates, not proof of IDOR/BOLA.</div></div>
            </div>
          </details>
          <div class="row" style="margin-top:14px"><label class="checkline"><input type="checkbox" id="ack"> I confirm this target and added hosts are authorized for security testing.</label></div>
          <div class="row" style="margin-top:14px"><button class="btn" id="start" type="submit">Start assessment</button><span id="msg" class="small" role="status" aria-live="polite"></span></div>
        </form>
      </section>
      <section class="grid">
        <div class="card"><div class="row between"><h2>Scan Jobs</h2><span class="small" id="scanCount">0 jobs</span></div><div id="scanList"></div></div>
        <div>
          <div class="card"><h2 id="detailTitle">Select a scan</h2><div id="detail"><div class="muted">Choose a job to inspect its status, findings, coverage, evidence, and reports.</div></div></div>
          <div class="card"><div class="row between"><h2>Findings</h2><span class="small" id="findingCount">0 findings</span></div><div id="findings"><div class="muted">Findings will appear here when a scan is selected.</div></div></div>
          <div class="card"><h2>Assessment detail</h2><div id="detailPanel" class="muted">Coverage and evidence details will appear here.</div></div>
        </div>
      </section>
      <div class="footer">FIREWATCH v9.0.0 · OWASP Top 10:2025 · ASVS 5.0.0 · WSTG v4.2 · API Security Top 10:2023. Coverage and automated findings do not prove the absence of vulnerabilities.</div>
    </main>`;

  $('#refresh').addEventListener('click', refreshScans);
  $('#scanForm').addEventListener('submit', startScan);
  $('#profile').addEventListener('change', applyProfile);
  $('#saveKey').addEventListener('click', saveApiKey);
  $('#apiKey').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') { event.preventDefault(); saveApiKey(); }
  });
}

function applyProfile() {
  const presets = {
    baseline: { pages: 100, depth: 4, delay: 300, browser: false, gql: false, probe: false, passive: true },
    standard: { pages: 300, depth: 8, delay: 150, browser: true, gql: true, probe: true, passive: false },
    comprehensive: { pages: 1500, depth: 12, delay: 200, browser: true, gql: true, probe: true, passive: false },
  };
  const value = presets[$('#profile').value];
  $('#pages').value = value.pages;
  $('#depth').value = value.depth;
  $('#delay').value = value.delay;
  $('#browser').checked = value.browser;
  $('#gql').checked = value.gql;
  $('#parameterProbes').checked = value.probe;
  $('#passive').checked = value.passive;
}

async function saveApiKey() {
  const field = $('#apiKey');
  const key = field.value.trim();
  if (key) sessionStorage.setItem('fw_api_key', key);
  else sessionStorage.removeItem('fw_api_key');
  field.value = '';
  try { await refreshScans(); }
  catch (error) { $('#msg').textContent = error.message; }
}

async function startScan(event) {
  event.preventDefault();
  const message = $('#msg');
  message.textContent = '';
  if (!$('#ack').checked) { message.textContent = 'Confirm the authorization checkbox before starting.'; return; }

  let requestHeaders;
  let authorizationProfiles;
  try {
    requestHeaders = parseJsonField('requestHeaders', 'Primary request headers', 'object');
    authorizationProfiles = parseJsonField('authProfiles', 'Authorization profiles', 'array');
    if (Object.values(requestHeaders).some((value) => typeof value !== 'string')) {
      throw new Error('Every primary request header value must be a string.');
    }
  } catch (error) { message.textContent = error.message; return; }

  const profile = $('#profile').value;
  const payload = {
    target_url: $('#url').value.trim(),
    scope_acknowledged: true,
    profile,
    max_pages: Number($('#pages').value),
    max_depth: Number($('#depth').value),
    max_endpoints: profile === 'comprehensive' ? 7000 : profile === 'baseline' ? 500 : 2000,
    max_concurrency: profile === 'comprehensive' ? 4 : profile === 'baseline' ? 2 : 3,
    request_delay_ms: Number($('#delay').value),
    enable_browser: profile !== 'baseline' && $('#browser').checked,
    enable_api_introspection: profile !== 'baseline' && $('#gql').checked,
    enable_safe_parameter_probes: profile !== 'baseline' && $('#parameterProbes').checked,
    respect_robots: $('#robots').checked,
    passive_only: profile === 'baseline' || $('#passive').checked,
    exclusions: listField('exclusions'),
    allowed_hosts: listField('allowedHosts'),
    request_headers: requestHeaders,
    auth_cookies: $('#authCookies').value || null,
    authorization_profiles: authorizationProfiles,
  };

  const button = $('#start');
  button.disabled = true;
  message.textContent = 'Creating scan job…';
  try {
    const created = await api('/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    // Clear credentials from editable controls after the server accepts the job.
    for (const id of ['requestHeaders', 'authCookies', 'authProfiles']) $(`#${id}`).value = '';
    selectedScanId = created.id;
    message.textContent = `Queued scan ${created.id}`;
    await refreshScans();
  } catch (error) {
    message.textContent = error.message;
  } finally { button.disabled = false; }
}

async function refreshScans() {
  const scans = await api('/scans?limit=100');
  scanCache = scans;
  $('#scanCount').textContent = `${scans.length} jobs`;
  renderScanList();
  if (selectedScanId) {
    if (scans.some((scan) => scan.id === selectedScanId)) await refreshDetail();
    else selectedScanId = null;
  }
}

function renderScanList() {
  if (!scanCache.length) {
    $('#scanList').innerHTML = '<div class="muted">No scans yet.</div>';
    return;
  }
  $('#scanList').innerHTML = scanCache.map((scan) => `
    <button class="scan-row ${selectedScanId === scan.id ? 'active' : ''}" type="button" data-scan-id="${esc(scan.id)}">
      <div>${esc(scan.target_url)}</div>
      <div class="row" style="margin-top:6px"><span class="badge ${esc(scan.status)}">${esc(scan.status.toUpperCase())}</span><span class="small">${prettyDate(scan.created_at)}</span></div>
    </button>`).join('');
  document.querySelectorAll('[data-scan-id]').forEach((button) => button.addEventListener('click', async () => {
    selectedScanId = button.dataset.scanId;
    renderScanList();
    try { await refreshDetail(); } catch (error) { showError(error); }
  }));
}

async function refreshDetail() {
  if (!selectedScanId) return;
  const scanId = selectedScanId;
  const [scan, findings, events, assets] = await Promise.all([
    api(`/scans/${scanId}`),
    api(`/scans/${scanId}/findings?limit=500`),
    api(`/scans/${scanId}/events?limit=500`),
    api(`/scans/${scanId}/assets?limit=300`),
  ]);
  if (selectedScanId !== scanId) return;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((finding) => { if (Object.hasOwn(counts, finding.severity)) counts[finding.severity] += 1; });
  const latest = events.at(-1);
  const progress = Math.max(0, Math.min(100, Number(latest?.progress || 0)));
  $('#detailTitle').textContent = scan.target_url;
  $('#findingCount').textContent = `${findings.length} findings`;
  $('#detail').innerHTML = `
    <div class="grid3">${Object.entries(counts).map(([severity, count]) => `<div class="metric"><span class="badge ${severity}">${severity.toUpperCase()}</span><strong>${count}</strong></div>`).join('')}</div>
    <div style="margin-top:14px"><div class="row"><span class="badge ${esc(scan.status)}">${esc(scan.status.toUpperCase())}</span><span class="small">Pages ${scan.pages_count} · Assets ${scan.assets_count} · Findings ${scan.findings_count} · Events ${scan.events_count}</span></div><div class="progress" style="margin-top:10px"><div style="width:${progress}%"></div></div><p class="small">${latest ? esc(`${latest.phase}: ${latest.message}`) : 'Waiting for scan events…'}</p>${scan.error ? `<p class="notice">${esc(scan.error)}</p>` : ''}</div>
    <div class="row action-row"><button class="btn secondary" data-report="html">HTML</button><button class="btn secondary" data-report="json">JSON</button><button class="btn secondary" data-report="csv">CSV</button><button class="btn secondary" data-report="markdown">Markdown</button><button class="btn secondary" data-report="sarif">SARIF</button><button class="btn secondary" id="downloadBundle">All reports ZIP</button><button class="btn secondary" id="showCoverage">Coverage</button><button class="btn secondary" id="showEvidence">Evidence</button><button class="btn secondary" id="compareScan">Compare baseline</button>${['queued', 'running'].includes(scan.status) ? '<button class="btn danger" id="cancelScan">Cancel scan</button>' : ''}</div>
    <details style="margin-top:14px"><summary>Execution timeline (${events.length})</summary><div class="table-wrap"><table class="table"><thead><tr><th>Phase</th><th>Progress</th><th>Event</th><th>Time</th></tr></thead><tbody>${events.map((event) => `<tr><td>${esc(event.phase)}</td><td>${esc(event.progress)}%</td><td>${esc(event.message)}</td><td>${prettyDate(event.created_at)}</td></tr>`).join('')}</tbody></table></div></details>
    <details style="margin-top:14px"><summary>Asset inventory (${assets.length} returned)</summary><div class="table-wrap"><table class="table"><thead><tr><th>Kind</th><th>Status</th><th>Method</th><th>URL</th></tr></thead><tbody>${assets.map((asset) => `<tr><td>${esc(asset.kind)}</td><td>${esc(asset.status_code ?? '—')}</td><td>${esc(asset.method)}</td><td class="endpoint">${esc(asset.url)}</td></tr>`).join('')}</tbody></table></div></details>`;
  $('#findings').innerHTML = findings.length ? findings.map((finding) => `
    <article class="finding"><div class="finding-head"><h3>${esc(finding.title)}</h3><span class="badge ${esc(finding.severity)}">${esc(finding.severity.toUpperCase())}</span></div>
      <div class="small">${esc(finding.rule_id)} · ${Math.round(Number(finding.confidence) * 100)}% confidence · risk ${esc(finding.risk_score)} · ${esc(finding.status)}</div>
      <p class="endpoint">${esc(finding.endpoint)}</p><p>${esc(finding.description)}</p><p><b>Impact:</b> ${esc(finding.impact)}</p><p><b>Evidence summary:</b> ${esc(finding.evidence_summary)}</p><p><b>Remediation:</b> ${esc(finding.remediation)}</p><p class="small">${esc((finding.references || []).join(' · '))}</p>
    </article>`).join('') : '<div class="muted">No findings recorded for this scan.</div>';
  document.querySelectorAll('[data-report]').forEach((button) => button.addEventListener('click', async () => {
    const format = button.dataset.report;
    const names = { html: 'report.html', json: 'report.json', csv: 'findings.csv', markdown: 'report.md', sarif: 'report.sarif.json' };
    try { await download(`/api/v1/scans/${scanId}/report?format=${encodeURIComponent(format)}`, names[format]); }
    catch (error) { showError(error); }
  }));
  $('#downloadBundle').addEventListener('click', async () => {
    try { await download(`/api/v1/scans/${scanId}/bundle`, `firewatch-${scanId}.zip`); }
    catch (error) { showError(error); }
  });
  $('#showCoverage').addEventListener('click', () => showCoverage(scanId));
  $('#showEvidence').addEventListener('click', () => showEvidence(scanId));
  $('#compareScan').addEventListener('click', () => compareScan(scanId));
  $('#cancelScan')?.addEventListener('click', async () => {
    try { await api(`/scans/${scanId}/cancel`, { method: 'POST' }); await refreshScans(); }
    catch (error) { showError(error); }
  });
}

async function showCoverage(scanId) {
  try {
    const result = await api(`/scans/${scanId}/coverage`);
    const rows = (result.catalog || []).map((item) => `<tr><td>${esc(item.category)}</td><td>${esc(item.status)}</td><td>${esc(item.finding_count ?? item.findings ?? 0)}</td><td>${esc(item.note || item.description || '')}</td></tr>`).join('');
    $('#detailPanel').innerHTML = `<p><b>Coverage interpretation:</b> ${esc(result.interpretation)}</p><p class="small">Pages: ${esc(result.pages_discovered)} · Assets: ${esc(result.assets_discovered)} · Findings: ${esc(result.findings_recorded)}</p><div class="table-wrap"><table class="table"><thead><tr><th>Category</th><th>Status</th><th>Findings</th><th>Notes</th></tr></thead><tbody>${rows || '<tr><td colspan="4">No catalog coverage rows returned.</td></tr>'}</tbody></table></div>`;
  } catch (error) { showError(error); }
}

async function showEvidence(scanId) {
  try {
    const items = await api(`/scans/${scanId}/evidence?limit=500`);
    $('#detailPanel').innerHTML = items.length ? `<p class="small">Evidence is returned after server-side redaction. Review before sharing outside your organization.</p><div class="table-wrap"><table class="table"><thead><tr><th>Finding ID</th><th>Kind</th><th>Evidence data</th><th>Created</th></tr></thead><tbody>${items.map((item) => `<tr><td>${esc(item.finding_id)}</td><td>${esc(item.kind)}</td><td><pre class="evidence-json">${esc(JSON.stringify(item.data, null, 2))}</pre></td><td>${prettyDate(item.created_at)}</td></tr>`).join('')}</tbody></table></div>` : '<div class="muted">No evidence records are available for this scan yet.</div>';
  } catch (error) { showError(error); }
}

async function compareScan(scanId) {
  try {
    const diff = await api(`/scans/${scanId}/diff`);
    const rows = (label, items) => items.length ? `<h3>${esc(label)} (${items.length})</h3><ul>${items.map((finding) => `<li>${esc(finding.severity?.toUpperCase())} · ${esc(finding.rule_id)} · ${esc(finding.title)} · ${esc(finding.endpoint)}</li>`).join('')}</ul>` : '';
    $('#detailPanel').innerHTML = `<p class="small">Baseline: ${esc(diff.baseline_scan_id || 'not available')} · Added ${diff.added.length} · Resolved ${diff.resolved.length} · Unchanged ${diff.unchanged.length}</p>${rows('New findings', diff.added)}${rows('Resolved candidates', diff.resolved)}${rows('Unchanged', diff.unchanged)}<p class="small">${esc(diff.message)}</p>`;
  } catch (error) { showError(error); }
}

function showError(error) {
  $('#msg').textContent = error?.message || String(error);
  $('#detailPanel').textContent = error?.message || String(error);
}

async function poll() {
  try { await refreshScans(); }
  catch (error) { $('#msg').textContent = error.message; }
  pollTimer = window.setTimeout(poll, 3000);
}

render();
poll();
