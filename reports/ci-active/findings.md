# WalletGuard generated security report

Generated: 2026-10-06T02:20:36.883973+00:00

This report contains actual scanner evidence. Zero findings only describes the successful listed coverage.

## Coverage

- security-tests / compose: success (exit 0)
- semgrep / secure-source: success (exit 0)
- pip-audit / runtime-dependencies: success (exit 0)
- trivy-config / deployment: success (exit 0)
- gitleaks / repository: success (exit 0)
- trivy-image / container:walletguard:local: success (exit 0)
- zap / http://wallet-api:8000:active: success (exit 0)

## Developer findings

### bab9815d03db72831fd0 — 10104

info | new | unreviewed | zap | http://wallet-api:8000

Evidence: User Agent Fuzzer   Method: GET; parameter: Header User-Agent; payload: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)

Reproduction: Rerun zap for scope http://wallet-api:8000:active; inspect rule 10104 at http://wallet-api:8000.

Impact: Assess exploitability and exposure from the preserved evidence.

Fix: Compare the same authenticated request with different User-Agent headers; review unexpected status codes or response data. This informational alert alone does not prove a vulnerability.

Retest: Pending developer retest

First seen: 2026-10-06T02:20:36.883973+00:00; last seen: 2026-10-06T02:20:36.883973+00:00

CWE: []; OWASP: []

### 5a7d0e2b05ee2af112bb — 10104

info | new | unreviewed | zap | http://wallet-api:8000/transfers

Evidence: User Agent Fuzzer   Method: POST; parameter: Header User-Agent; payload: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)

Reproduction: Rerun zap for scope http://wallet-api:8000:active; inspect rule 10104 at http://wallet-api:8000/transfers.

Impact: Assess exploitability and exposure from the preserved evidence.

Fix: Compare the same authenticated request with different User-Agent headers; review unexpected status codes or response data. This informational alert alone does not prove a vulnerability.

Retest: Pending developer retest

First seen: 2026-10-06T02:20:36.883973+00:00; last seen: 2026-10-06T02:20:36.883973+00:00

CWE: []; OWASP: []

### 9b8e6444f337cf4b3bd2 — 10104

info | new | unreviewed | zap | http://wallet-api:8000/wallets

Evidence: User Agent Fuzzer   Method: POST; parameter: Header User-Agent; payload: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)

Reproduction: Rerun zap for scope http://wallet-api:8000:active; inspect rule 10104 at http://wallet-api:8000/wallets.

Impact: Assess exploitability and exposure from the preserved evidence.

Fix: Compare the same authenticated request with different User-Agent headers; review unexpected status codes or response data. This informational alert alone does not prove a vulnerability.

Retest: Pending developer retest

First seen: 2026-10-06T02:20:36.883973+00:00; last seen: 2026-10-06T02:20:36.883973+00:00

CWE: []; OWASP: []
