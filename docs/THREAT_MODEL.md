# FIREWATCH v9 Threat Model

## Purpose and security boundary

FIREWATCH is an assessment coordinator for systems that the operator owns or is authorized to test. It is not a network isolation boundary, exploit framework, or proof that a target is secure. The operator's egress firewall/proxy and approved engagement scope remain authoritative.

## Assets to protect

- API keys, bearer tokens, cookies and authorization profile material.
- The scan database, encryption key and report directory.
- Target identifiers, endpoint inventory, finding details and evidence.
- The integrity and provenance of generated reports and release artifacts.
- The availability of the FIREWATCH service and assessed targets.

## Trust boundaries

1. Dashboard/client to FastAPI API.
2. API to persistence and encrypted secret storage.
3. Worker to assessed HTTP targets and optional browser process.
4. Worker to optional ZAP service.
5. Report archive and evidence crossing into a developer, ticketing system, or CI artifact store.
6. Source repository and CI build environment to public release packages.

## Principal threats and mitigations

| Threat | Mitigation in v9 | Residual risk |
|---|---|---|
| Unauthorized scan submission | API-key gate; production requires a strong configured key; scope acknowledgement | API keys still need rotation and secret-manager storage |
| SSRF/internal-service probing | strict URL/scope checks, conservative private-address policy, bounded read-only requests | DNS rebinding/time-of-check/time-of-use is not solved solely by application checks; enforce egress rules outside the process |
| Credential forwarding | credentials are encrypted at rest and isolated to exact root origin | compromised host process or browser can still access in-memory credentials |
| Secret leaks in evidence/reports | redaction of URL/query/fields and bundle review tests | redaction is heuristic; review exports before sharing |
| Report/archive tampering | SHA-256 manifest with each report's path and byte count | manifest is not signed; a hostile party can replace both report and manifest |
| Resource exhaustion | page, depth, endpoint, concurrency, request-delay and timeout ceilings | target-side latency and browser memory still require OS/container limits |
| Insecure production configuration | startup validation for limits, API key, database, private targets, worker topology, CORS and ZAP origin | secret rotation, TLS termination and network policies remain deployment responsibilities |
| Unsafe test behavior | built-in probes are bounded and non-destructive; manual/exploit-required cases are labeled separately | authorization/business logic still requires test fixtures and human review |
| Supply-chain drift | CI, Dependabot, CodeQL workflow and declared-dependency inventory | these workflows have to run in GitHub; local package audits need package-index access |

## Explicit non-goals

The default engine does not perform password guessing, credential stuffing, arbitrary write/delete requests, destructive workflow tests, executable XSS payloads, exploit-style SQL/OS injection, or weaponized SSRF. Review candidates are not proof of exploitability.

## Deployment assumptions

- Production is deployed behind TLS and an allow-listed ingress.
- Outbound traffic from the service is constrained by firewall/proxy policy to approved targets.
- The data volume and encryption key are access-controlled and backed up consistently.
- Reports and logs are treated as potentially confidential customer/security data.
- Operators use dedicated, least-privileged test identities and remove them after engagement.
