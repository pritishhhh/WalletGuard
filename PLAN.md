# WalletGuard implementation plan

This repository is an authorized internal API security template. All money is simulated INR minor units. No payment, bank, or customer integrations are in scope.

| Milestone | Delivery | Acceptance check |
|---|---|---|
| 1 | Threat model, requirements, architecture decisions | Review risks and versioned OWASP mappings before application code |
| 2 | FastAPI, PostgreSQL, migrations, immutable ledger, authentication | Migrate a fresh database; register, fund, transfer, reconcile |
| 3 | Ownership, strict input, persistent rate limits, safe profiles | Two-user denial, mass-assignment, production config tests |
| 4 | Behavioral and parallel tests | No overspend, balanced entries, replay/conflict, persistence, migration checks |
| 5 | Semgrep, pip-audit, Trivy, Gitleaks | Real JSON outputs; fail on scanner errors; explicit severity/exception gate |
| 6 | Allowlisted ZAP Automation Framework, authenticated checks | Preflight rejects unauthorized origins; passive and manual active plans execute |
| 7 | Findings CLI, baseline, triage, Markdown/HTML/JSON | Parse actual scanner outputs, stable dedup, scoped fixed/suppressed handling |
| 8 | Isolated vulnerable teaching fixture | Preserve actual detection and secure retest evidence |
| 9 | Compose, CI, demo, operations docs | Documented fresh start; upload reports; accurate observed results and blockers |

## Decisions

- PostgreSQL only: use database row locks and transaction-scoped advisory locks; no in-memory financial locks or SQLite substitute.
- Argon2id passwords and random opaque bearer sessions stored as digests; organization identity providers replace local registration/authentication.
- Double-entry transfers and local funding use the same ledger. A dedicated simulated treasury is allowed a negative balance; user wallets are never allowed negative balances.
- PostgreSQL triggers enforce ledger immutability and deferred balancing. Reconciliation checks cached balances against entries in a consistent snapshot.
- Scanners stay separate. Local download/install attempts are allowed; environmental blockers are recorded without inventing results.
- No external messages, production deployment, real funds, or public scans are authorized by this project.

See PROGRESS.md for measured milestone outcomes.
