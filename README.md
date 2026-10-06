# WalletGuard

A PostgreSQL-backed digital wallet API and reusable **authorized internal security testing workflow**. All funds are simulated INR minor units. No bank, payment network or real customer integration exists. The default application excludes the deliberately vulnerable teaching fixture.

Verified on 6 October 2026: **58 passing tests**, successful SAST/dependency/secret/configuration/image scans, and authenticated passive and active DAST. Each DAST profile confirmed five cross-user requests were denied. Passive ZAP returned zero alerts; active ZAP retained three informational observations. See the successful [passive CI run](https://github.com/pritishhhh/WalletGuard/actions/runs/37402573152), [active CI run](https://github.com/pritishhhh/WalletGuard/actions/runs/37402854364), and committed evidence in [reports/ci-passive](reports/ci-passive) and [reports/ci-active](reports/ci-active). The [failure analysis and fix](docs/ci-dast-fix.md) explain the repaired scanner startup timeout.

## Start locally

Prerequisites: Python 3.12+, Docker Desktop/Engine with Compose 2.24.4+ (running), and network access for public package/image/scanner downloads. Clone or extract this directory and work from its root.

```sh
python scripts/init_local.py --start
```

This generates a random ignored .env database password, builds the non-root API image, starts PostgreSQL, applies migrations, and waits for readiness. Open http://127.0.0.1:8000/docs. Stop without deleting data: `docker compose down`. Only when intentionally discarding synthetic data: `docker compose down --volumes`.

Set up host tooling:

```sh
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` on Windows or `source .venv/bin/activate` on Linux/macOS, then:

```sh
python -m pip install -r requirements-dev.txt
python -m scripts.demo --open-report
```

The demo creates two synthetic users and wallets, funds 1,000 minor units, transfers 100, prints the sender's 900 balance, and verifies five denied cross-user requests. It does not print access tokens. API workflow: POST /auth/register → POST /auth/login → POST /wallets → local POST /wallets/{id}/fund → POST /transfers → GET /wallets/{id}/transactions. Use `Authorization: Bearer <session>` and an `Idempotency-Key` of 8–128 letters/digits/._- for each money movement. Repeat the same key/content for a replay; different content returns 409. See docs/api-workflow.md for an executable example.

## Tests and migrations

Tests require a **separate disposable PostgreSQL database whose name ends in _test**. The suite deliberately truncates that database; it refuses other names. No SQLite or memory-only financial substitute is used.

Start a separate local test database (shell commands below use synthetic CI-only trust authentication on loopback):

```sh
docker run --rm -d --name walletguard-tests -p 127.0.0.1:5433:5432 -e POSTGRES_DB=walletguard_test -e POSTGRES_USER=walletguard -e POSTGRES_HOST_AUTH_METHOD=trust postgres:17.11-bookworm
```

Wait for `docker exec walletguard-tests pg_isready -U walletguard` to succeed. Windows:

```powershell
$env:TEST_DATABASE_URL='postgresql+psycopg://walletguard@127.0.0.1:5433/walletguard_test'
$env:DATABASE_URL=$env:TEST_DATABASE_URL
```

Linux/macOS:

```sh
export TEST_DATABASE_URL=postgresql+psycopg://walletguard@127.0.0.1:5433/walletguard_test
export DATABASE_URL="$TEST_DATABASE_URL"
```

```sh
python -m alembic upgrade head
python -m pytest -q --junitxml=reports/current/pytest.xml
python -m pytest -q -m stress
python -m walletguard.cli reconcile --output reports/current/reconciliation.json
python -m ruff check walletguard security tests scripts teaching migrations
```

Set DATABASE_URL to the intended application database before operational reconciliation. For the running Compose application, run `docker compose exec wallet-api python -m walletguard.cli reconcile --output /tmp/reconciliation.json`. Stop the disposable tests with `docker stop walletguard-tests`.

If Docker is unavailable but PostgreSQL is already running, create an application database and a separate *_test database, set those two URLs using a generated password, then run `python -m alembic upgrade head` and `python -m uvicorn walletguard.app:create_app --factory --host 127.0.0.1 --port 8000 --no-server-header --no-access-log`. The same demo, tests and portable scanner commands apply. This native path was used for the actual results in this environment.

## Security scans and reports

Install scanner tooling separately to avoid dependency conflicts with the API:

```sh
python -m venv security/.runtime/scanners
```

Activate it and install `python -m pip install -r security/scanners.in`, then return to the application virtual environment. Install pinned, checksum-verified Trivy/Gitleaks binaries:

```sh
python scripts/install_scanners.py
```

Add the scanner environment's Scripts (Windows) or bin (Linux/macOS) and security/.runtime/bin to PATH; or pass explicit --semgrep/--pip-audit/--trivy/--gitleaks paths. On Windows an explicit command is:

```powershell
python -m security.config_check
python -m security.scan static --semgrep security/.runtime/scanners/Scripts/semgrep.exe --pip-audit security/.runtime/scanners/Scripts/pip-audit.exe --trivy security/.runtime/bin/trivy.exe --gitleaks security/.runtime/bin/gitleaks.exe
python -m security.scan container --trivy security/.runtime/bin/trivy.exe --image walletguard:local
```

Linux/macOS x64:

```sh
python -m security.config_check
python -m security.scan static --semgrep security/.runtime/scanners/bin/semgrep --pip-audit security/.runtime/scanners/bin/pip-audit --trivy security/.runtime/bin/trivy --gitleaks security/.runtime/bin/gitleaks
python -m security.scan container --trivy security/.runtime/bin/trivy --image walletguard:local
```

ZAP runs with Docker against the exact allowlisted Compose service. On Linux, set `WG_SCAN_UID` and `WG_SCAN_GID` to the host user/group IDs so mounted reports remain writable:

```sh
export WG_SCAN_UID=$(id -u) WG_SCAN_GID=$(id -g)
python -m security.dast --config security/target.ci.json --seed-wallet --compose --profile passive
python -m security.dast --config security/target.ci.json --seed-wallet --compose --profile active --output reports/active
```

On Windows omit the export line. Portable ZAP with Java 17+ is also supported:

```sh
python -m security.dast --config security/target.local.json --seed-wallet --profile passive --zap-jar /path/to/ZAP_2.17.0/zap-2.17.0.jar
```

For another owned API, edit the target configuration with exact origin, allowlist, authorization description, identity endpoint and OpenAPI endpoint; list explicitly authorized private hosts when needed. Set WG_SCAN_TOKEN to a valid normal-user bearer token and omit --seed-wallet. External/public origins and external OpenAPI references are refused. Use a disposable target for active scanning; do not point this project at production or third-party systems.

```sh
python -m security.findings --manifest reports/current/manifest.json --output reports/current --gate
python -m security.findings --manifest reports/current/manifest.json --baseline reports/sample/findings.json --output reports/current --gate
python -m teaching.evidence
```

reports/current contains raw scanner JSON, the coverage manifest, and unified findings.json / findings.md / findings.html. Open the HTML directly in a browser. reports/sample is a real generated, sanitized snapshot; reports/teaching preserves intentional findings. Lifecycle: new, existing, fixed only after a successful same-scope scan, suppressed with accountable unexpired exception, or unverified when coverage is missing. Developer handoff includes reproduction, impact, fix and retest. See docs/security-policy.md for gates/triage/limitations.

## Layout

```text
walletguard/            API, configuration, ORM, ledger service, operations CLI
migrations/            Initial PostgreSQL schema and Alembic revision
tests/                 Behavioral, ownership, concurrency, config, report and fixture tests
security/              Scanner runners, parsers, policies, target configs and ZAP plans
teaching/              Isolated vulnerable fixture and actual behavioral detector
scripts/               Local start, synthetic demo, dependency lock and scanner installer
reports/sample/        Real generated sanitized scan report and JUnit evidence
reports/ci-passive/    Passing full CI evidence with provenance and SHA-256 index
reports/ci-active/     Passing active CI evidence with informational findings
reports/teaching/      Intentional vulnerability evidence
.github/workflows/     CI tests, migrations, scans, report gate and artifacts
docs/                  Threat model, OWASP mapping, architecture, remediation and operations
PLAN.md / PROGRESS.md  Milestone acceptance checks and observed outcomes
Dockerfile / compose*  Local reference deployment and production-oriented overlay
```

PR CI uses PostgreSQL integration tests, explicit migrations, Semgrep, dependency/secret/config scans, a built-image vulnerability scan, and passive authenticated ZAP. Active ZAP requires an explicit workflow_dispatch flag. Failures are not hidden. SARIF upload is deliberately omitted; JSON/HTML/Markdown and diagnostics are uploaded as artifacts without assuming code-scanning entitlement.

Actual measured results, remaining environment/CI limitations and truthful resume bullets are in docs/results.md and PROGRESS.md. Production adoption requires the checklist in docs/operations.md; this repository does not claim ASVS certification or readiness for real-money custody.
