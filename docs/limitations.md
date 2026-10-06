# Verification limits and adoption gaps

Native PostgreSQL migrations, functional/security/concurrency tests, real Semgrep/pip-audit/Gitleaks/Trivy configuration scans, explicit Compose policy checks, and both ZAP profiles ran locally. Consult docs/results.md and the actual reports for counts. No fabricated scan output or performance figures are included.

The local Windows Docker engine remains unavailable. Docker was installed outside PATH; its client reports Docker 29.7.2 and Compose 5.3.1, and Compose validates the configuration. The engine pipe was absent and a bounded query after startup did not receive a response. No operating-system settings were changed. This limits local Windows container verification; Linux GitHub Actions now verifies the actual Docker build/start, migrations, built-image vulnerability scan and both DAST profiles. Run `python scripts/init_local.py --start` and the documented image scan after restoring the local engine to repeat those checks on Windows.

Full [passive CI](https://github.com/pritishhhh/WalletGuard/actions/runs/37402573152) and [active CI](https://github.com/pritishhhh/WalletGuard/actions/runs/37402854364) passed on 6 October 2026, with 58 tests each and all required security coverage. Sanitized snapshots with tested-commit provenance are committed under reports/ci-passive and reports/ci-active. The older reports/sample snapshot preserves its original missing local image coverage. Passing these checks does not resolve the production adoption gaps below or constitute security certification.

Windows native scanners initially failed on socket initialization. Replacing the short-name temporary directory with a resolved workspace directory fixed Semgrep. For Java/ZAP on this host, set a quoted `-Djdk.net.unixdomain.tmpdir` to the same directory via JAVA_TOOL_OPTIONS. Example PowerShell (choose a real existing directory with a short absolute path):

```powershell
$taskTemp=(Resolve-Path ./temp).Path
$env:TEMP=$taskTemp
$env:TMP=$taskTemp
$env:TMPDIR=$taskTemp
$env:JAVA_TOOL_OPTIONS='-Djdk.net.unixdomain.tmpdir="'+$taskTemp+'"'
```

Create temp first if needed. Prefer the Docker scanner where a working engine exists. One installed Starlette test-client deprecation warning remains; it does not fail the tests. Native verification used Python 3.12.6 and PostgreSQL 17.11. GitHub Actions also exercised the digest-pinned Alpine application image successfully.

The security template intentionally targets loopback or explicitly authorized private network origins only. For an organization-owned public staging API, run behind an approved private tunnel/proxy or extend preflight and egress policy after review. Preflight is not a substitute for network egress restrictions; native ZAP is a trusted local tool and should only run on a controlled target without external redirects. Compose keeps the database and scanner on an internal network; the API also joins a host bridge to make its loopback port reachable. Apply additional API egress policy in production if required. Absolute-origin URL references and remote OpenAPI refs are refused.

Local auth has no MFA/reset/recovery, identity-provider integration, recipient name verification or fraud screening. Rate limiting uses fixed windows and socket peer IP; add trusted ingress controls and tune cleanup/limits for production. No holds, multilateral settlement, currencies beyond INR or real money are supported. Ledger/audit immutability does not protect against an administrator with DDL/superuser privileges. Add external append-only audit retention. The full audit export is unbounded for small demonstrations; use controlled incremental collection for large deployments.

The seven Semgrep rules are narrow, not a complete security review. They detect SQL interpolation/debug/CORS in the teaching fixture but miss BOLA. Behavioral tests cover that gap. Trivy scans the Dockerfile, not Compose; explicit config checks cover the local Compose controls. ZAP's routine profile imports GETs only; the active profile is time bounded and does not prove business logic or authorization. User Agent Fuzzer informational observations are retained and are not presented as confirmed exploitable vulnerabilities.

Dependency/image/scanner downloads require PyPI, GitHub, Docker registries, Semgrep distribution endpoints, PyPI advisory service and Trivy databases/check bundles. Versions/digests are pinned where practical; advisory databases change over time. Refresh locks/digests with reviewed upgrades and rerun gates. Do not publish internal raw reports without redaction/review.
