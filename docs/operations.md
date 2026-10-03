# Operations and incident procedure

Run `python -m walletguard.cli reconcile --output reports/current/reconciliation.json` with DATABASE_URL set. It reads a repeatable-read snapshot, checks exactly two correctly signed equal entries per transfer, checks every wallet's cached balance against its entire ledger, and verifies nonnegative user balances. Exit 1 is an integrity incident. Never repair a mismatch by editing immutable entries; freeze movement at ingress, preserve backups/logs, investigate, and use a reviewed compensating transfer or restore procedure.

For an incident, record time, request ID, actor UUID and transfer UUID from audit/logs. Export append-only events using `python -m walletguard.cli export-audit --output reports/current/audit.json`. Restrict the export to investigators, correlate it with gateway/identity-provider logs, and preserve it with an integrity checksum and organization retention policy. Successful monetary actions and replay events are audited atomically. Denied calls are audited independently; database outages can prevent this write, and emit audit_write_failed. The current log sink is standard error; configure centralized collection and alerts on 401/403/404 spikes, 429, 503, reconciliation failures and audit failures.

Revoke a compromised identity's sessions using a reviewed operator command such as a bound SQL delete on sessions.user_id or the organization's IdP revocation mechanism. Normal users can revoke their current session through POST /auth/logout. Never include raw tokens or passphrases in incident tickets. The local implementation has no password reset, MFA or account recovery; adopt an IdP before deployment to real users.

Back up PostgreSQL using pg_dump for the local demo and managed point-in-time recovery for production. Test restores on an isolated database, run Alembic/current and reconciliation after restore, and confirm audit/ledger retention. Do not downgrade or delete the ledger to solve a migration failure. Take backups before changes and apply reviewed forward migrations with a separate migration owner. Runtime identities must not own tables or have TRUNCATE/DDL permissions.

Schedule `python -m walletguard.cli cleanup` to remove expired sessions and rate buckets older than one day. It does not remove ledger or audit history. The audit export currently reads the full table; large deployments should use controlled incremental export or a database audit integration.

## Deployment checklist

- Disable simulated funding and local signup; configure the production profile and allowed hosts.
- Generate separate migration/runtime secrets through a secret manager; apply docs/runtime-grants.sql; remove superuser/DDL privileges.
- Terminate TLS at a trusted reverse proxy, enforce HTTPS, verified PostgreSQL TLS, approved CORS origins and ingress body limits.
- Replace local identity with an OIDC/OAuth2 provider using a maintained verifier, strict issuer/audience checks, bounded JWKS refresh, MFA policy and local subject mapping; preserve ownership checks and digest/session revocation behavior.
- Add edge throttling per trusted client/identity, tune database limits and connection pools, and test multiple replicas.
- Confirm backups, restore drills, point-in-time recovery and audit retention; encrypt and restrict artifacts.
- Apply forward migrations before rollout; run readiness, reconciliation, two-user denial and concurrency tests.
- Review dependency/container advisories, medium/low alerts and any expiring exceptions; enforce branch protection on CI.
- Monitor errors/denials, latency, DB lock waits and audit failures; define incident ownership and rollback controls.
- Run active DAST only on disposable synthetic deployments with an exact allowlist and isolated egress.

## Runtime image maintenance

The API uses the digest-pinned official Python 3.12 Alpine 3.24 image. Install only prebuilt runtime dependency wheels, then remove pip from the final image. Native build tools and a package installer are unnecessary at runtime. The first GitHub image scan rejected the Debian Bookworm base due to its reported OS vulnerabilities; the replacement base had zero OS findings in a direct Trivy scan on 3 October 2026. CI scans the complete built image with the same severity policy. Refresh the digest and rerun the full workflow when updating the image.
