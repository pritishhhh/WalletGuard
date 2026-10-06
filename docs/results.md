# Observed results

## Full GitHub Actions acceptance — 6 October 2026

Both profiles passed against commit `6a33f5cf1493c71d0a66ac287e92a0de7b60fbd5`: [passive run 37402573152](https://github.com/pritishhhh/WalletGuard/actions/runs/37402573152) and [active run 37402854364](https://github.com/pritishhhh/WalletGuard/actions/runs/37402854364). These runs exercised the actual Docker deployment on Linux, including migrations, readiness, authenticated requests and the built-image scan.

| Check | Verified result in both full CI runs |
|---|---|
| Behavioral/security/workflow tests | **58 passed**, zero failures or errors; passive 17.896 seconds, active 17.380 seconds |
| Semgrep, pip-audit and Gitleaks | Completed successfully with zero findings |
| Trivy configuration and built image | Completed successfully with zero findings; Compose policy checks also passed |
| Authenticated API identity | Expected HTTP 200 |
| Cross-user authorization | Five protected requests returned HTTP 404 in each profile |
| Passive ZAP | Automation Framework completed; zero alerts |
| Active ZAP | Automation Framework completed; one informational User Agent Fuzzer alert with three instances, retained as three informational observations |
| Reconciliation and consolidated gate | Passed; every required scanner coverage entry succeeded |

Sanitized raw outputs, JUnit, authorization checks, reconciliation, unified reports and run/commit provenance are committed in [reports/ci-passive](../reports/ci-passive) and [reports/ci-active](../reports/ci-active). Each snapshot includes a SHA-256 index; report line endings are fixed to LF so evidence hashes remain consistent across platforms. [CI failure analysis](ci-dast-fix.md) documents the startup failure, fix and passing retests. These are measured results for the tested commit and advisory database state, not a guarantee against all vulnerabilities.

## Historical native verification — 3 October 2026

| Check | Actual observation |
|---|---|
| Fresh PostgreSQL migrations | Alembic revision 0001 applied to application, initial test and fresh final test databases on PostgreSQL 17.11 |
| Final behavioral/workflow suite | Fresh database: **54 passed in 28.00 seconds**; final code rerun: **54 passed in 24.25 seconds**, one Starlette deprecation warning; actual final JUnit saved |
| Parallel withdrawal stress | 64 attempts, 16 worker threads, 1,000 starting units, 30 requested each: 33 success, 31 insufficient funds, balances 10 and 990; balanced reconciliation |
| Parallel replay/reverse transfers | 16 same-key retries produced one transfer ID; 32 opposite-direction transfers all completed; reconciliation passed |
| Ownership and tampering | Wallet detail/history/fund/source transfer and nonparticipant transaction requests denied; extra role/owner/balance/ledger/system fields rejected |
| Session/abuse controls | Password hashes Argon2id, digest-only tokens, expiry/logout, strict values, body limits, persistent limits, safe errors/logs and production config tests passed |
| Semgrep 1.179.0 | Seven configured rules; secure-source scan completed with zero findings; teaching fixture produced three actual SAST findings (SQL, debug, wildcard CORS) |
| pip-audit 2.10.1 | Runtime dependency scan completed, zero advisory findings at run time |
| Gitleaks 8.30.1 | Repository scan completed, zero potential secrets found |
| Trivy 0.75.0 configuration | Dockerfile scan completed, zero configuration findings; explicit Compose policy check also zero findings |
| ZAP 2.17.0 passive | Automation plan succeeded, normal-user protected requests returned expected 200, zero alerts |
| ZAP 2.17.0 active | Automation plan succeeded; three informational User Agent Fuzzer findings; no higher-severity alerts |
| Live authenticated authorization checks | Five cross-account checks returned 404 in each profile: wallet/history/fund/funding transaction/source transfer |
| Native wallet reconciliation | Observed snapshot: 12 transfers / 24 entries, no unbalanced transfers or wallet mismatches; later demo runs add synthetic entries |
| Compose syntax/config | Installed Compose 5.3.1 validates local and production overlay configurations; overlay validation used synthetic settings |
| Documented demo | Executed against the restarted current API: synthetic sender balance 900, five cross-account denials 404 |
| Container build/start/image scan | Blocked by unavailable/unresponsive Docker Desktop engine; no image scan pass claimed |
| GitHub Actions | Workflow implemented and pinned; remote CI not run in this session |

reports/sample is generated from actual current tool outputs plus the real active scan; teaching findings are preserved separately in reports/teaching. It records missing container coverage instead of pretending that a clean static scan covers an image. Reports are sanitized and copied with a SHA-256 evidence index. Read docs/remediation.md for the concrete fixture detection → secure implementation → passing retest trail. Intentional teaching weaknesses remain isolated and are not suppressed as secure code.

## Truthful resume bullets

- Built a FastAPI/PostgreSQL wallet API with Argon2id authentication, ownership checks, an immutable double-entry ledger and database-backed idempotency; passed 58 behavioral/security tests, including 64 parallel withdrawals with zero overspend and balanced reconciliation.
- Implemented a passing CI security pipeline using Semgrep, pip-audit, Gitleaks, Trivy configuration/image checks and authenticated OWASP ZAP passive/active scans; verified five cross-user denials per profile and documented detection, fixes and secure retests for isolated BOLA, SQL injection and unsafe CORS fixtures.
