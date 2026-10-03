# Progress

## Milestone 1 — completed

Created PLAN.md, threat model and versioned security requirement mapping before application implementation. Verified the workspace contains no existing repository code. Environment: Windows, Python 3.12.6, Java 17; Docker command unavailable; WSL distribution enumeration returns E_ACCESSDENIED. Public dependency network access requires the execution environment's network permission.

## Milestones 2–4 — completed application checks

Downloaded portable PostgreSQL 17.11 and initialized two loopback-only databases with generated credentials. Initial migration errors (driver percent handling and a reserved column name) were repaired before acceptance. Migrations succeeded on both the application and test databases. First complete test run: **37 passed in 24.50s**; JUnit evidence saved. Parallel withdrawal: 64 attempts × 30 minor units against 1,000; 33 succeed, 31 return 409, source balance 10, destination 990. Parallel same-key retry and opposite-direction tests also passed. Database triggers reject ledger/audit modification, unbalanced entries, negative user balances and cached balance drift. Restart persistence, ownership, tampering, auth and limits passed.

## Milestones 5–9 — in progress

Completed verification is recorded below; milestones retain their earlier measured results.

## Milestones 5–8 — verified natively

Ran Semgrep 1.179.0 (seven rules, zero secure-source findings), pip-audit 2.10.1 (zero advisories), Gitleaks 8.30.1 (zero potential secrets), and Trivy 0.75.0 Dockerfile checks (zero misconfigurations). Explicit Compose policy checks pass; Trivy does not parse Compose here. Repaired Windows temp socket errors and scanner output UTF-8 handling. ZAP 2.17.0 passive and active Automation Framework plans both succeeded after correcting plan parameters and bearer host scoping. Normal-user requests returned expected 200; five two-user cross-account probes returned 404. Passive: zero alerts. Active: three informational User Agent Fuzzer observations, retained for triage.

Teaching fixture generated three behavioral detections; its SAST report contains three actual findings (SQL/debug/CORS). Secure ownership/injection/CORS regression tests pass; BOLA is documented as a Semgrep limitation. Report parser/baseline/dedup/redaction/exception/error tests pass. The fixture is excluded from the image and default app.

## Milestone 9 — implementation delivered; external acceptance work remains

Fresh-database test suite: **54 passed in 28.00s**; final error-normalization rerun: **54 passed in 24.25s**, one test-client deprecation warning. Created Compose, production overlay, pinned CI workflow, operating procedures, scan policy, remediation evidence, README, executable demo, and reusable target configuration. Installed Compose validates local and production syntax. Docker Desktop is installed outside PATH; initial engine pipe is absent and a bounded query after startup has no response. Ubuntu Docker integration is disabled. Therefore Compose runtime/image scanning cannot yet be accepted. At local delivery, remote GitHub Actions had not run. The repository is now being published to https://github.com/pritishhhh/WalletGuard; check its Actions tab for the current remote verification result. Detailed commands and limitations are documented; the project is **not marked fully accepted** while these external checks remain.

## Repository publication � remote verification

Published the project to https://github.com/pritishhhh/WalletGuard. Initial Actions run 37101587220 passed 54 tests, migrations, static/configuration/secret checks and Docker build/start. Its image scan correctly blocked the Debian Bookworm base (58 high, five critical, one unknown OS package findings). Replaced that base with a digest-pinned official Python 3.12 Alpine 3.24 image, verified compatible binary wheels and removed pip from the runtime image. Direct base scan: zero OS findings. A complete workflow rerun is required before claiming remote acceptance.
