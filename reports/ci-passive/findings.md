# WalletGuard generated security report

Generated: 2026-10-06T02:20:36.347226+00:00

This report contains actual scanner evidence. Zero findings only describes the successful listed coverage.

## Coverage

- security-tests / compose: success (exit 0)
- semgrep / secure-source: success (exit 0)
- pip-audit / runtime-dependencies: success (exit 0)
- trivy-config / deployment: success (exit 0)
- gitleaks / repository: success (exit 0)
- trivy-image / container:walletguard:local: success (exit 0)
- zap / http://wallet-api:8000:passive: success (exit 0)

## Developer findings

No findings in successful scan outputs. Authorization and business logic still require behavioral tests.