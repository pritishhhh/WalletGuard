# WalletGuard generated security report

Generated: 2026-10-02T22:41:02.166203+00:00

This report contains actual scanner evidence. Zero findings only describes the successful listed coverage.

## Coverage

- semgrep / isolated-teaching: success (exit 0)
- security-tests / isolated-teaching: success (exit 0)

## Developer findings

### 5cc6cb5ddb4c3ecf41af — security.walletguard-sql-interpolation

high | new | confirmed | semgrep | teaching/vulnerable.py

Evidence: line 21: SQL assembled from interpolated input; use bound parameters.

Reproduction: Rerun semgrep for scope isolated-teaching; inspect rule security.walletguard-sql-interpolation at teaching/vulnerable.py.

Impact: Teaching fixture exposes unauthorized data or unsafe configuration; it is excluded from the deployed image.

Fix: SQL assembled from interpolated input; use bound parameters.

Retest: Secure counterpart regression tests passed; teaching fixture intentionally retains the weakness.

First seen: 2026-10-02T22:41:02.166203+00:00; last seen: 2026-10-02T22:41:02.166203+00:00

CWE: ['CWE-89']; OWASP: ['A05:2025 Injection']

### 0467dc8675a29cb98781 — WG-SQL-001

high | new | confirmed | security-tests | teaching/vulnerable.py:/search

Evidence: owner=alice' OR 1=1-- returned both Alice and Bob rows (2).

Reproduction: Rerun security-tests for scope isolated-teaching; inspect rule WG-SQL-001 at teaching/vulnerable.py:/search.

Impact: Teaching fixture exposes unauthorized data or unsafe configuration; it is excluded from the deployed image.

Fix: Use bound SQL and validated UUIDs; secure API injection regression returns 422.

Retest: Secure counterpart regression tests passed; teaching fixture intentionally retains the weakness.

First seen: 2026-10-02T22:41:02.166203+00:00; last seen: 2026-10-02T22:41:02.166203+00:00

CWE: ['CWE-89']; OWASP: ['A05:2025']

### ab80902e0d2c50db6ee2 — WG-BOLA-001

high | new | confirmed | security-tests | teaching/vulnerable.py:/wallets/{id}

Evidence: Unauthenticated GET /wallets/1 returned HTTP 200 with Alice balance 1000.

Reproduction: Rerun security-tests for scope isolated-teaching; inspect rule WG-BOLA-001 at teaching/vulnerable.py:/wallets/{id}.

Impact: Teaching fixture exposes unauthorized data or unsafe configuration; it is excluded from the deployed image.

Fix: Require bearer [REDACTED] and owner predicate; secure API test_cross_user_wallet_endpoints returns 404.

Retest: Secure counterpart regression tests passed; teaching fixture intentionally retains the weakness.

First seen: 2026-10-02T22:41:02.166203+00:00; last seen: 2026-10-02T22:41:02.166203+00:00

CWE: ['CWE-639']; OWASP: ['API1:2023', 'A01:2025']

### 42387f54fde12aec64bd — WG-CORS-001

medium | new | confirmed | security-tests | teaching/vulnerable.py

Evidence: Untrusted Origin preflight returned access-control-allow-origin: *.

Reproduction: Rerun security-tests for scope isolated-teaching; inspect rule WG-CORS-001 at teaching/vulnerable.py.

Impact: Teaching fixture exposes unauthorized data or unsafe configuration; it is excluded from the deployed image.

Fix: Default to no permitted cross-origin clients; secure API preflight omits allow-origin.

Retest: Secure counterpart regression tests passed; teaching fixture intentionally retains the weakness.

First seen: 2026-10-02T22:41:02.166203+00:00; last seen: 2026-10-02T22:41:02.166203+00:00

CWE: ['CWE-942']; OWASP: ['A02:2025']

### 5a887033545cf564668d — security.walletguard-wildcard-cors

medium | new | confirmed | semgrep | teaching/vulnerable.py

Evidence: line 9: Wildcard CORS exposes API responses to arbitrary origins; define explicit origins.

Reproduction: Rerun semgrep for scope isolated-teaching; inspect rule security.walletguard-wildcard-cors at teaching/vulnerable.py.

Impact: Teaching fixture exposes unauthorized data or unsafe configuration; it is excluded from the deployed image.

Fix: Wildcard CORS exposes API responses to arbitrary origins; define explicit origins.

Retest: Secure counterpart regression tests passed; teaching fixture intentionally retains the weakness.

First seen: 2026-10-02T22:41:02.166203+00:00; last seen: 2026-10-02T22:41:02.166203+00:00

CWE: ['CWE-942']; OWASP: ['A02:2025 Security Misconfiguration']

### aadfcf8f86d21f2173c8 — security.walletguard-debug

medium | new | confirmed | semgrep | teaching/vulnerable.py

Evidence: line 8: Debug mode may expose sensitive exception details; disable it in deployed applications.

Reproduction: Rerun semgrep for scope isolated-teaching; inspect rule security.walletguard-debug at teaching/vulnerable.py.

Impact: Teaching fixture exposes unauthorized data or unsafe configuration; it is excluded from the deployed image.

Fix: Debug mode may expose sensitive exception details; disable it in deployed applications.

Retest: Secure counterpart regression tests passed; teaching fixture intentionally retains the weakness.

First seen: 2026-10-02T22:41:02.166203+00:00; last seen: 2026-10-02T22:41:02.166203+00:00

CWE: ['CWE-209']; OWASP: ['A02:2025 Security Misconfiguration']
