-- Run as migration/database administrator AFTER migrations.
-- Create walletguard_runtime separately with a generated secret in your secret manager.
-- Never use a SUPERUSER, table-owner, CREATEDB or BYPASSRLS runtime identity.
GRANT CONNECT ON DATABASE walletguard TO walletguard_runtime;
GRANT USAGE ON SCHEMA public TO walletguard_runtime;
GRANT SELECT ON users,sessions,wallets,transfers,entries,audit,rate_buckets,alembic_version TO walletguard_runtime;
GRANT INSERT ON users,sessions,wallets,transfers,entries,audit,rate_buckets TO walletguard_runtime;
GRANT UPDATE (password_hash) ON users TO walletguard_runtime;
GRANT UPDATE (balance_minor) ON wallets TO walletguard_runtime;
GRANT UPDATE (count) ON rate_buckets TO walletguard_runtime;
GRANT DELETE ON sessions,rate_buckets TO walletguard_runtime;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO walletguard_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
