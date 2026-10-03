# WalletGuard generated security report

Generated: 2026-10-02T22:41:02.158203+00:00

This report contains actual scanner evidence. Zero findings only describes the successful listed coverage.

## Coverage

- semgrep / secure-source: success (exit 0)
- pip-audit / runtime-dependencies: success (exit 0)
- trivy-config / deployment: success (exit 0)
- gitleaks / repository: success (exit 0)
- security-tests / compose: success (exit 0)
- zap / http://127.0.0.1:8000:passive: success (exit 0)
- trivy-image / container:walletguard:local: unavailable (exit None)
- zap / http://127.0.0.1:8000:active: success (exit 0)
- INCOMPLETE: trivy-image (container:walletguard:local): unavailable

## Developer findings

### 52a4087a13e54ffb4254 — 10104

info | new | unreviewed | zap | http://127.0.0.1:8000

Evidence: User Agent Fuzzer   Method: GET; parameter: Header User-Agent; payload: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)

Reproduction: Rerun zap for scope http://127.0.0.1:8000:active; inspect rule 10104 at http://127.0.0.1:8000.

Impact: Assess exploitability and exposure from the preserved evidence.

Fix: Compare the same authenticated request with different User-Agent headers; review unexpected status codes or response data. This informational alert alone does not prove a vulnerability.

Retest: Pending developer retest

First seen: 2026-10-02T22:41:02.158203+00:00; last seen: 2026-10-02T22:41:02.158203+00:00

CWE: []; OWASP: []

### 8e9b3d664923898beed6 — 10104

info | new | unreviewed | zap | http://127.0.0.1:8000/transfers

Evidence: User Agent Fuzzer   Method: POST; parameter: Header User-Agent; payload: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)

Reproduction: Rerun zap for scope http://127.0.0.1:8000:active; inspect rule 10104 at http://127.0.0.1:8000/transfers.

Impact: Assess exploitability and exposure from the preserved evidence.

Fix: Compare the same authenticated request with different User-Agent headers; review unexpected status codes or response data. This informational alert alone does not prove a vulnerability.

Retest: Pending developer retest

First seen: 2026-10-02T22:41:02.158203+00:00; last seen: 2026-10-02T22:41:02.158203+00:00

CWE: []; OWASP: []

### 81047d8d4be1b2323e2e — 10104

info | new | unreviewed | zap | http://127.0.0.1:8000/wallets/

Evidence: User Agent Fuzzer   Method: GET; parameter: Header User-Agent; payload: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)

Reproduction: Rerun zap for scope http://127.0.0.1:8000:active; inspect rule 10104 at http://127.0.0.1:8000/wallets/.

Impact: Assess exploitability and exposure from the preserved evidence.

Fix: Compare the same authenticated request with different User-Agent headers; review unexpected status codes or response data. This informational alert alone does not prove a vulnerability.

Retest: Pending developer retest

First seen: 2026-10-02T22:41:02.158203+00:00; last seen: 2026-10-02T22:41:02.158203+00:00

CWE: []; OWASP: []
