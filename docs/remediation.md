# Detection → secure implementation → retest

The teaching module is deliberately vulnerable, test-only, has no default server entry point, and is excluded from the Docker image. It remains vulnerable to teach detection; it is never mislabeled as fixed. The secure counterpart is walletguard/app.py plus the service layer. Generated reports/teaching contains actual detections; the secure application's JUnit and scanner reports contain retest evidence.

| Finding | Actual detection | Secure change | Retest |
|---|---|---|---|
| WG-BOLA-001 | In-process GET /wallets/1 with no identity returned 200 with Alice's 1,000 balance | Bearer identity required; owner-filtered wallet query; transaction view restricted to participants | Cross-user detail/history/funding/transfer and outsider transaction tests pass with 404; no token gets 401; live two-user DAST prechecks also return 404 |
| WG-SQL-001 | `alice' OR 1=1--` returned two rows from the teaching search; Semgrep flags its concatenated execute | Bound SQLAlchemy queries; strict UUID routes and strict amount models | Secure injection request returns 422; secure source SAST returns zero findings under configured rules |
| WG-CORS-001 | Untrusted Origin got access-control-allow-origin: *; Semgrep detects wildcard middleware | Empty allowed origins by default; production forbids wildcard origins and insecure origins | Untrusted preflight has no allow-origin header; unsafe production settings are rejected |
| Debug configuration | Semgrep detects FastAPI(debug=True) in teaching fixture | Secure FastAPI has no debug flag, safe error envelopes and no credential echo | Secure SAST has no debug finding; error tests verify safe response text |

Scanner limitations: the configured Semgrep rules do **not** infer wallet ownership. They missed BOLA; the behavioral detector and two-user tests caught it. ZAP is not proof of BOLA/property authorization or financial concurrency. OpenAPI-generated invalid UUIDs produce validation errors; requestor jobs additionally request real owned wallets, and dedicated pytest tests exercise transfers with valid state. No claim of a historical vulnerable production deployment is made: this is an isolated fixture-to-secure-counterpart demonstration with real evidence.

Reproduce: `python -m teaching.evidence`, `semgrep scan --config security/semgrep.yml --metrics off --disable-version-check --json --output reports/teaching/semgrep.json teaching/vulnerable.py`, then `python -m pytest -q tests/test_wallet.py -k 'cross_user or injection or cors'`. Re-run secure source SAST with `python -m security.scan static`. The fixture is separately scoped from secure-source so its intentional findings do not silently disappear in baseline comparisons.
