# Threat model

## Assets and actors

Assets: password hashes, session digests, wallet ownership, exact balances, immutable ledger, idempotency records, audit history, scan evidence, source and dependency integrity. Actors: unauthenticated attacker, malicious authenticated customer, internal developer/scanner, deployment operator, compromised application/database administrator. All identities and funds in the reference environment are synthetic.

## Trust boundaries

Untrusted client → TLS proxy → API validation/authentication → authorization/service → PostgreSQL transaction and constraints. Scanner → exact authorized target origin is a separate boundary. Build/CI → package registries is a supply-chain boundary. Operators with database superuser access can bypass triggers; this project does not claim protection from a malicious superuser. Logs and report artifacts require internal access controls.

## Abuse cases and priorities

| Priority | Abuse | Control and verification |
|---|---|---|
| P0 | Change wallet or transaction UUID to read/withdraw another customer's funds (BOLA) | Owner predicate on every resource read; source ownership before movement; two-user tests |
| P0 | Submit concurrent withdrawals or reverse-direction transfers | Ordered PostgreSQL FOR UPDATE locks, CHECK constraint, parallel stress and reconciliation |
| P0 | Replay or change a transfer under an idempotency key | User-scoped transaction advisory lock, content hash, unique constraint; 409 on conflict |
| P0 | Negative, float, boolean, overflowing or tampered amounts | Strict positive integer minor units bounded per request; no writable balance/ledger/role fields |
| P1 | Account takeover via credential stuffing/session theft | Argon2id, bounded passwords, uniform login failure, persistent IP and account limits, expiry/revocation; TLS required outside local |
| P1 | Escalate role or call local funding in production | No privileged client role; strict extra-field rejection; production startup disallows funding |
| P1 | SQL/command injection | SQLAlchemy bound parameters; Semgrep and isolated injection regression fixture |
| P1 | Expose secrets through logs, source or scan reports | No request bodies/tokens in logs; digest-only sessions; Gitleaks; evidence redaction |
| P1 | Unsafe CORS, exposed database, permissive deployment | Deny CORS by default; loopback Compose API; internal DB; non-root read-only container; configuration scans |
| P1 | Suppress alerts or destroy audit/ledger evidence | Append-only audit/ledger triggers, transactional monetary audit, request IDs, validated expiring exceptions |
| P2 | Oversized/chunked requests, auth hash exhaustion, unbounded history | Streaming body size enforcement, persistent limits before hashing, bounded pagination |
| P2 | Scan unintended host or leak DAST credentials | Exact origin allowlist, loopback/internal host restriction, no redirects, scoped ZAP header, filtered OpenAPI |
| P2 | Partial scanner run mistaken for clean/fixed findings | Coverage manifest, strict parsers, missing tool status, baseline fixes only for successful matching scopes |

Residual risks: no MFA, password recovery, fraud engine, recipient verification, distributed edge throttling, payment compliance or tamper-proof external audit storage. Database rate limits are a template control; production should add ingress throttling. Active scanning can create synthetic state and is limited to disposable environments.
