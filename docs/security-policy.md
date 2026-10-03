# Scanner, triage and exception policy

Versions: Semgrep 1.179.0; pip-audit 2.10.1; Trivy 0.75.0; Gitleaks 8.30.1; ZAP 2.17.0. Python runtime dependencies and direct developer dependencies are pinned. Python/PostgreSQL base images and GitHub Actions are pinned to verified digests/commits. ZAP core is version pinned; bundled add-ons are the ones from that release, not automatically upgraded. Vulnerability databases and current advisories necessarily change; record tool versions and generated timestamps.

Seven checked-in Semgrep rules target Python SQL interpolation, shell execution, debug mode, wildcard CORS, unsafe deserialization, disabled TLS verification, and dynamic evaluation. They are intentionally reproducible/offline after tool installation and narrower than a complete managed SAST rule suite. Extend organization rules after review. Behavioral tests detect ownership issues that these rules miss. Trivy scans the Dockerfile and built image. It does not parse Compose in this version; security.config_check supplies explicit Compose checks and tests them against unsafe examples.

Gate: scanner unavailable/failed/malformed outputs fail; unsuppressed high or critical findings fail; unknown dependency severity fails conservatively because pip-audit does not provide reliable CVSS severity for every advisory. Medium/low/informational findings remain visible for developer review. The ZAP exit-status job warns at medium and fails at high; completed alert runs are consolidated by the same severity gate. A crashed plan, failed identity request or report missing after the run is a failed scan. There is no continue-on-error.

Only security/exceptions.json suppresses gates. Each exact finding ID must have `reason`, `owner`, and ISO `expires`; expired entries are rejected. A false-positive triage label alone does not suppress a gate. Example structure (replace the illustrative ID with a real finding ID):

```json
[{"id":"actual-finding-id","reason":"Documented isolated exposure and compensating control","owner":"security-team","expires":"2026-11-01"}]
```

Use security/triage.json to map a finding ID to `state` (confirmed, false-positive, accepted-risk, investigating), `owner`, `reason`, and optionally `reproduction`, `impact`, `recommended_fix`, `retest_result`. Keep exceptions reviewed in the same pull request as any compensating control. No exceptions are present by default. Teaching reports contain confirmed deliberately vulnerable findings and are separate from the secure application gate.

Raw scanner reports are internal evidence, not public artifacts. The Gitleaks runner uses --redact. ZAP traditional-json omits complete request/response headers; runtime plans and sessions are ignored and excluded from CI artifacts. The unified report retains source tool, component, severity, evidence, CWE/OWASP mapping if supplied, developer fix, lifecycle status and first/last seen dates. Missing coverage produces an incomplete report; a clean report is never a claim of exhaustive security.

Sources: [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/), [ZAP bearer header handling](https://www.zaproxy.org/docs/getting-further/authentication/handling-auth-yourself/), [Semgrep Community Edition](https://semgrep.dev/products/community-edition/).
