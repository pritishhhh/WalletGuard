# Deploy the API on Vercel

The repository exports the actual WalletGuard application as `main:app` and explicitly selects it in `[tool.vercel]` in pyproject.toml. Vercel previously found only the `app` fixture in tests/conftest.py because walletguard/app.py exports a factory, not a module-level application. Never use `tests.conftest:app`: that is a pytest fixture for a disposable test database.

## Project configuration

Import pritishhhh/WalletGuard with the repository root as Root Directory and FastAPI as Framework Preset. Leave Build Command and Output Directory at their framework defaults. The pinned dependencies in pyproject.toml install the full API runtime, including argon2-cffi for password hashing. They match requirements.txt; scripts/lock.py updates both, and CI rejects divergence. Vercel uses the project manifest when present, so a pyproject.toml containing metadata without dependencies can build but produce a function missing its imports. No Docker build, uvicorn command or static output directory is needed.

Vercel hosts the API function, not the PostgreSQL container or security scanner containers. Connect a hosted PostgreSQL database reachable from Vercel. Set these variables in Vercel Project Settings for each environment you deploy:

| Variable | Value |
|---|---|
| `DATABASE_URL` | Hosted PostgreSQL connection string; the Neon integration supplies this automatically when connected to Production |
| `DATABASE_URL_UNPOOLED` | Direct provider connection, supplied by Neon; preferred on Vercel to preserve PostgreSQL session/transaction semantics |
| `WG_PROFILE` | `production` |
| `WG_LOCAL_FUNDING` | `false` |
| `WG_ALLOWED_HOSTS` | Exact comma-separated hostnames, without `https://`: your production domain, deployment/preview domains you intend to use and any custom domain; do not use `*` |
| `WG_CORS_ORIGINS` | Leave empty for server-to-server access, or set exact HTTPS frontend origins |

On Vercel (`VERCEL=1`), the application defaults to the production profile. It converts a provider's `postgres://` or `postgresql://` prefix to the required psycopg driver, prefers the direct URL when supplied, upgrades `sslmode=require` to `verify-full`, and supplies the bundled certifi CA roots when no explicit CA path is provided. Other provider parameters are preserved. Disabled TLS is still rejected. Native deployments retain the explicit connection requirements documented elsewhere. Keep connection strings in Vercel environment settings, not in Git or chat. Missing DATABASE_URL or invalid settings fail startup explicitly; a green Vercel build alone does not verify runtime readiness.

For a new database, open this project's Storage page, create a Neon database on the Free plan and connect it to Production with sensitive environment variables. The provider agreement must be accepted by the account owner or with their explicit approval. Creating the database and connecting the project are both necessary; the source-code dependency fix alone cannot supply DATABASE_URL.

## Database and redeployment

Before serving wallet requests, apply the migrations to that hosted database from a trusted machine with the pinned dependencies installed. Set DATABASE_URL securely in that process, then run:

```sh
python -m alembic upgrade head
```

When migrating a Neon integration URL locally, select its direct DATABASE_URL_UNPOOLED connection, use the `postgresql+psycopg` driver and verified TLS with trusted CA roots. Do not set TEST_DATABASE_URL to the deployment database or run the destructive integration test suite against it. Migrations are an explicit provisioning step, not a cold-start task.

Redeploy the latest main commit after saving the settings. Confirm `GET /health` returns HTTP 200 and `GET /ready` returns HTTP 200. Health checks application startup; readiness additionally confirms database access and the migration revision. The root `/` returns an API overview with service name and health/readiness/schema paths. Production disables Swagger `/docs` and simulated funding by design. Existing account/wallet/transfer routes continue to use the same application and PostgreSQL ledger.

GitHub Actions remains responsible for SAST, container scans and disposable-target DAST. Vercel hosting does not run those Docker jobs. Size hosted-database connection limits for multiple function instances: each process currently permits a pool of 20 connections plus 20 overflow connections. Use an appropriate provider pooler and validate compatibility with the PostgreSQL advisory-lock and transaction behavior before increasing traffic.

References: [Vercel FastAPI entrypoints and deployment](https://vercel.com/docs/frameworks/backend/fastapi), [Vercel environment variables](https://vercel.com/docs/environment-variables).
