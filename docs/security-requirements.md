# Security requirements

Frameworks: OWASP Top 10 **2025**, OWASP API Security Top 10 **2023**, OWASP ASVS **5.0.0**. ASVS references below are chapter-level implementation mappings, not a certification or a claim that every chapter requirement is satisfied.

| ID | Requirement | Top 10 2025 | API 2023 | ASVS 5.0 chapter | Evidence |
|---|---|---|---|---|---|
| SR01 | Authenticated ownership for each object | A01 | API1, API5 | V8 Authorization | Two-user resource tests |
| SR02 | Reject writable role, balance, owner and ledger fields | A01, A08 | API3 | V2 Validation and Business Logic; V8 | Tampering tests |
| SR03 | Exact money, ordered DB locks, atomic balanced ledger | A06, A08, A10 | API6 | V2; V15 Secure Coding and Architecture | Parallel transfer and trigger tests, reconciliation |
| SR04 | Idempotent retry, conflict on changed content | A06, A08 | API6 | V2 | Replay/concurrency tests |
| SR05 | Argon2id, secure sessions, expiry, logout | A04, A07 | API2 | V6 Authentication; V7 Session Management | Auth/session tests |
| SR06 | Strict validation and bound SQL | A05 | API3 | V1 Encoding and Sanitization; V2 | Semgrep and injection regression |
| SR07 | Body/rate/page limits | A06, A10 | API4, API6 | V2; V4 API and Web Service | Limits tests |
| SR08 | Safe configuration, narrow CORS, TLS boundary | A02, A04 | API8 | V3 Web Frontend Security; V12 Secure Communication; V13 Configuration | Production config tests, Trivy, ZAP |
| SR09 | No secrets in source, logs or reports | A04, A09 | API8 | V11 Cryptography; V14 Data Protection; V16 Security Logging and Error Handling | Gitleaks, redaction tests |
| SR10 | Correlated audit, consistent safe errors | A09, A10 | API8 | V16 | Audit/error tests |
| SR11 | Pinned supply chain and scanner gates | A03, A08 | API9, API10 | V13; V15 | pip-audit, Trivy, reviewed exceptions |
| SR12 | Explicit scan authorization and OpenAPI inventory | A01, A02 | API7, API9, API10 | V4; V13 | Allowlist preflight tests and coverage manifest |

Authoritative references: [Top 10 2025](https://top10.owasp.org/2025/0x00_2025-Introduction/), [API Top 10 2023](https://owasp.org/projects/api-security-project), [ASVS release](https://github.com/OWASP/ASVS/tree/v5.0.0). Maintainers must review requirement-level gaps before organizational adoption.
