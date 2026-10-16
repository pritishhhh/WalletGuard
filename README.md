# WalletGuard

[![Security checks](https://github.com/pritishhhh/WalletGuard/actions/workflows/security.yml/badge.svg)](https://github.com/pritishhhh/WalletGuard/actions/workflows/security.yml)

**A simulated digital wallet API built to demonstrate application security, financial correctness, and verifiable security testing.**

WalletGuard combines a PostgreSQL-backed wallet service with an automated security pipeline. Users can register, authenticate, create wallets, transfer simulated funds, and inspect transaction history. The project follows the full security workflow: identify threats, implement controls, detect weaknesses, document findings, and verify fixes through retesting.

[Live API](https://wallet-guard-omega.vercel.app/) | [API workflow](docs/api-workflow.md) | [Security evidence](docs/results.md)

## Core idea

A wallet must protect both **who can access money** and **how money moves**. WalletGuard addresses these together: ownership checks prevent cross-user access, while database constraints, transactions, and locking preserve balances during concurrent requests and retries. Automated scans complement behavioral tests that exercise authorization and business logic.

All funds are simulated INR minor units. The project has no bank or payment-network integration.

## Key capabilities

- **Authentication:** Argon2id password hashing, digest-only bearer-session storage, expiration, and logout revocation.
- **Authorization:** Owner-scoped wallet access and participant-only transaction visibility, with cross-user denial tests.
- **Ledger integrity:** Immutable double-entry records, atomic transfers, integer amounts, database-enforced constraints, and reconciliation.
- **Concurrency and retries:** Ordered database locking and persistent idempotency prevent overspending and duplicate money movements.
- **API protection:** Strict input validation, persistent rate limiting, audit events, safe error responses, and security headers.

## Security testing workflow

GitHub Actions runs PostgreSQL integration tests, migrations, reconciliation, SAST, dependency and secret checks, configuration checks, a built-image vulnerability scan, and authenticated passive DAST. Active DAST runs through an explicit manual workflow against a disposable target.

An isolated teaching fixture demonstrates BOLA, SQL injection, unsafe CORS, and debug exposure. It is excluded from the application image. Findings are linked to reproduction steps, secure implementation changes, and passing retests; behavioral authorization tests cover weaknesses that the configured static rules cannot detect.

The reporting pipeline consolidates scanner outputs into JSON, HTML, and Markdown, tracks scan coverage and finding lifecycle, and enforces severity and missing-coverage gates. Committed evidence includes sanitized outputs, run provenance, and SHA-256 indexes.

## Tech stack

| Area | Technologies |
|---|---|
| Backend | Python, FastAPI, Pydantic, Argon2id |
| Database | PostgreSQL, SQLAlchemy, Alembic, psycopg |
| Testing and quality | pytest, HTTPX, Ruff |
| Security analysis | Semgrep, OWASP ZAP, Trivy, Gitleaks, pip-audit |
| Delivery and hosting | Docker, Docker Compose, GitHub Actions, Vercel, Neon PostgreSQL |

## Verified results

- **63 tests passed** in the [16 October 2026 security workflow](https://github.com/pritishhhh/WalletGuard/actions/runs/38856049914).
- **64 concurrent withdrawal attempts** against 1,000 starting units produced 33 successful withdrawals and 31 insufficient-funds responses, with no overspend and balanced reconciliation.
- Recorded [passive](reports/ci-passive) and [active](reports/ci-active) scan evidence confirms **five cross-user denials per profile**. Passive scanning reported zero alerts; active scanning retained three informational observations.

These results describe the tested versions and recorded scan scope. Production adoption gaps and security-testing limits are documented in [limitations](docs/limitations.md).

## Explore the project

| Path | Purpose |
|---|---|
| `walletguard/` | API, authentication, ledger, persistence, and operational commands |
| `security/` | Scanner runners, ZAP plans, finding parsers, and security policies |
| `tests/` | Authorization, concurrency, ledger, configuration, and reporting tests |
| `teaching/` | Isolated vulnerable examples and detection evidence |
| `reports/` | Sanitized findings, test results, and scan evidence |
| `docs/` | Architecture, threat model, API behavior, and remediation records |

Further reading: [Architecture](docs/architecture.md), [Threat model](docs/threat-model.md), [Security policy](docs/security-policy.md), and [Findings and remediation](docs/remediation.md).
