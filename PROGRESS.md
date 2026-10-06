# Progress

## Milestone 1 — completed

Created PLAN.md, threat model and versioned security requirement mapping before application implementation. Verified the workspace contains no existing repository code. Environment: Windows, Python 3.12.6, Java 17; Docker command unavailable; WSL distribution enumeration returns E_ACCESSDENIED. Public dependency network access requires the execution environment's network permission.

## Milestones 2–4 — completed application checks

Downloaded portable PostgreSQL 17.11 and initialized two loopback-only databases with generated credentials. Initial migration errors (driver percent handling and a reserved column name) were repaired before acceptance. Migrations succeeded on both the application and test databases. First complete test run: **37 passed in 24.50s**; JUnit evidence saved. Parallel withdrawal: 64 attempts × 30 minor units against 1,000; 33 succeed, 31 return 409, source balance 10, destination 990. Parallel same-key retry and opposite-direction tests also passed. Database triggers reject ledger/audit modification, unbalanced entries, negative user balances and cached balance drift. Restart persistence, ownership, tampering, auth and limits passed.

## Milestones 5–9 — completed with remote acceptance on 6 October 2026

Completed verification is recorded below; milestones retain their earlier measured results.

## Milestones 5–8 — verified natively

Ran Semgrep 1.179.0 (seven rules, zero secure-source findings), pip-audit 2.10.1 (zero advisories), Gitleaks 8.30.1 (zero potential secrets), and Trivy 0.75.0 Dockerfile checks (zero misconfigurations). Explicit Compose policy checks pass; Trivy does not parse Compose here. Repaired Windows temp socket errors and scanner output UTF-8 handling. ZAP 2.17.0 passive and active Automation Framework plans both succeeded after correcting plan parameters and bearer host scoping. Normal-user requests returned expected 200; five two-user cross-account probes returned 404. Passive: zero alerts. Active: three informational User Agent Fuzzer observations, retained for triage.

Teaching fixture generated three behavioral detections; its SAST report contains three actual findings (SQL/debug/CORS). Secure ownership/injection/CORS regression tests pass; BOLA is documented as a Semgrep limitation. Report parser/baseline/dedup/redaction/exception/error tests pass. The fixture is excluded from the image and default app.

## Milestone 9 — implementation delivered; external acceptance work remains

Fresh-database test suite: **54 passed in 28.00s**; final error-normalization rerun: **54 passed in 24.25s**, one test-client deprecation warning. Created Compose, production overlay, pinned CI workflow, operating procedures, scan policy, remediation evidence, README, executable demo, and reusable target configuration. Installed Compose validates local and production syntax. Docker Desktop is installed outside PATH; initial engine pipe is absent and a bounded query after startup has no response. Ubuntu Docker integration is disabled. Therefore Compose runtime/image scanning cannot yet be accepted. At local delivery, remote GitHub Actions had not run. The repository is now being published to https://github.com/pritishhhh/WalletGuard; check its Actions tab for the current remote verification result. Detailed commands and limitations are documented; the project is **not marked fully accepted** while these external checks remain.

## Repository publication — remote verification

Published the project to https://github.com/pritishhhh/WalletGuard. Initial Actions run 37101587220 passed 54 tests, migrations, static/configuration/secret checks and Docker build/start. Its image scan correctly blocked the Debian Bookworm base (58 high, five critical, one unknown OS package findings). Replaced that base with a digest-pinned official Python 3.12 Alpine 3.24 image, verified compatible binary wheels and removed pip from the runtime image. Direct base scan: zero OS findings. A complete workflow rerun is required before claiming remote acceptance.

Second Actions run 37101973237 verified the rebuilt Alpine application starts and its full container vulnerability gate passes. Host-side DAST preparation then failed to reach the healthy API on the internal-only bridge. Added a separate host bridge for the API, retained database/migration/scanner isolation and added a host readiness check. DAST now records failed coverage before preflight, so preparation errors cannot produce a clean consolidated report. Seventeen focused workflow/deployment regression tests and Compose syntax checks pass; the full remote rerun remains the acceptance check.

## Full CI and DAST acceptance — 6 October 2026

Run 37102369547 then exposed a scanner startup timeout. Diagnostic run 37401792339 preserved the previously discarded logs and showed Java preferences and Selenium cache could not write to the default ZAP home: the image uses UID 1000, while the CI runner uses UID 1001. Moved HOME, Java user.home/preferences and the browser cache into the writable report mount, configured the bundled Firefox executable, added a write probe and retained redacted timeout diagnostics with targeted container cleanup. The scanner still runs without root privileges on its internal-only network. Nineteen focused workflow/deployment tests passed locally.

Fix commit `6a33f5cf1493c71d0a66ac287e92a0de7b60fbd5` passed the complete [passive workflow](https://github.com/pritishhhh/WalletGuard/actions/runs/37402573152) and [active workflow](https://github.com/pritishhhh/WalletGuard/actions/runs/37402854364). Both passed **58 tests**, migrations, reconciliation, source/dependency/secret/configuration scans, real Docker build/start, image scanning, authenticated ZAP and the final report gate. Each profile confirmed five cross-user denials. Passive: zero alerts. Active: one informational User Agent Fuzzer alert with three instances, retained as three observations. Committed sanitized evidence includes provenance and SHA-256 indexes in reports/ci-passive and reports/ci-active. This completes the project CI acceptance checks; production adoption gaps remain documented in docs/limitations.md and docs/operations.md.
