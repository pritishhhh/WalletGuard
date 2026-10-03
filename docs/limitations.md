# Verification limits and adoption gaps

Native PostgreSQL migrations, functional/security/concurrency tests, real Semgrep/pip-audit/Gitleaks/Trivy configuration scans, explicit Compose policy checks, and both ZAP profiles ran locally. Consult docs/results.md and the actual reports for counts. No fabricated scan output or performance figures are included.

Docker was installed outside PATH. Its client reports Docker 29.7.2 and Compose 5.3.1. Compose validates the local configuration. The engine initially failed with `open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified`; after starting the existing Desktop installation, a bounded engine query did not receive a response. The existing Ubuntu WSL distribution reports Docker integration disabled. No operating-system settings were changed to bypass this. Therefore the built-container/startup path and container vulnerability scan remain **unverified**, pending a working Docker engine. The image scanner is configured and CI invokes it; it has not produced a local image vulnerability result. Run `python scripts/init_local.py --start` and `python -m security.scan container --image walletguard:local --trivy <trivy-path>` after fixing the engine.

GitHub Actions is implemented with pinned official action commits. At local delivery, workflow structure/configuration had been checked locally and remote CI had not run. See https://github.com/pritishhhh/WalletGuard/actions for current runs and uploaded artifacts; the local sample reports do not claim a green remote run. Both missing container verification and remote CI evidence remain acceptance work; the project is not labeled fully accepted.

Windows native scanners initially failed on socket initialization. Replacing the short-name temporary directory with a resolved workspace directory fixed Semgrep. For Java/ZAP on this host, set a quoted `-Djdk.net.unixdomain.tmpdir` to the same directory via JAVA_TOOL_OPTIONS. Example PowerShell (choose a real existing directory with a short absolute path):

```powershell
$taskTemp=(Resolve-Path ./temp).Path
$env:TEMP=$taskTemp
$env:TMP=$taskTemp
$env:TMPDIR=$taskTemp
$env:JAVA_TOOL_OPTIONS='-Djdk.net.unixdomain.tmpdir="'+$taskTemp+'"'
```

Create temp first if needed. Prefer the Docker scanner where a working engine exists. One installed Starlette test-client deprecation warning remains; it does not fail the 54 tests. Tests run on Python 3.12.6 and PostgreSQL 17.11. The image's pinned Python version/OS environment has not yet been exercised.

The security template intentionally targets loopback or explicitly authorized private network origins only. For an organization-owned public staging API, run behind an approved private tunnel/proxy or extend preflight and egress policy after review. Preflight is not a substitute for network egress restrictions; native ZAP is a trusted local tool and should only run on a controlled target without external redirects. Compose uses an internal network. Absolute-origin URL references and remote OpenAPI refs are refused.

Local auth has no MFA/reset/recovery, identity-provider integration, recipient name verification or fraud screening. Rate limiting uses fixed windows and socket peer IP; add trusted ingress controls and tune cleanup/limits for production. No holds, multilateral settlement, currencies beyond INR or real money are supported. Ledger/audit immutability does not protect against an administrator with DDL/superuser privileges. Add external append-only audit retention. The full audit export is unbounded for small demonstrations; use controlled incremental collection for large deployments.

The seven Semgrep rules are narrow, not a complete security review. They detect SQL interpolation/debug/CORS in the teaching fixture but miss BOLA. Behavioral tests cover that gap. Trivy scans the Dockerfile, not Compose; explicit config checks cover the local Compose controls. ZAP's routine profile imports GETs only; the active profile is time bounded and does not prove business logic or authorization. User Agent Fuzzer informational observations are retained and are not presented as confirmed exploitable vulnerabilities.

Dependency/image/scanner downloads require PyPI, GitHub, Docker registries, Semgrep distribution endpoints, PyPI advisory service and Trivy databases/check bundles. Versions/digests are pinned where practical; advisory databases change over time. Refresh locks/digests with reviewed upgrades and rerun gates. Do not publish internal raw reports without redaction/review.
