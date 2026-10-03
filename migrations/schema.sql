CREATE TABLE users (
 id uuid PRIMARY KEY, username varchar(40) UNIQUE NOT NULL, password_hash varchar(256) NOT NULL,
 role varchar(16) NOT NULL CHECK (role = 'user')
);
CREATE TABLE sessions (
 digest varchar(64) PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE wallets (
 id uuid PRIMARY KEY, owner_id uuid REFERENCES users(id), label varchar(60) NOT NULL,
 currency varchar(3) NOT NULL CHECK (currency = 'INR'), balance_minor bigint NOT NULL DEFAULT 0,
 system boolean NOT NULL DEFAULT false,
 CHECK (system OR balance_minor >= 0), CHECK (balance_minor <= 9000000000000000),
 CHECK ((system AND owner_id IS NULL) OR (NOT system AND owner_id IS NOT NULL))
);
CREATE INDEX ix_wallets_owner_id ON wallets(owner_id);
CREATE UNIQUE INDEX one_treasury ON wallets(system) WHERE system;
INSERT INTO wallets VALUES ('00000000-0000-0000-0000-000000000001', NULL, 'SIMULATED TREASURY', 'INR', 0, true);
CREATE TABLE transfers (
 id uuid PRIMARY KEY, actor_id uuid NOT NULL REFERENCES users(id), source_id uuid NOT NULL REFERENCES wallets(id),
 destination_id uuid NOT NULL REFERENCES wallets(id), amount_minor bigint NOT NULL CHECK (amount_minor > 0 AND amount_minor <= 1000000000),
 kind varchar(16) NOT NULL CHECK (kind IN ('transfer','local_funding')), idempotency_key varchar(128) NOT NULL,
 request_hash varchar(64) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(actor_id,idempotency_key), CHECK (source_id <> destination_id)
);
CREATE TABLE entries (
 id bigserial PRIMARY KEY, transfer_id uuid NOT NULL REFERENCES transfers(id), wallet_id uuid NOT NULL REFERENCES wallets(id),
 delta_minor bigint NOT NULL CHECK(delta_minor <> 0), UNIQUE(transfer_id,wallet_id)
);
CREATE INDEX ix_entries_transfer_id ON entries(transfer_id);
CREATE INDEX ix_entries_wallet_id ON entries(wallet_id);
CREATE TABLE audit (
 id bigserial PRIMARY KEY, actor_id uuid, action varchar(64) NOT NULL, object_id varchar(64),
 request_id varchar(64) NOT NULL, outcome varchar(16) NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_request ON audit(request_id);
CREATE TABLE rate_buckets (key varchar(64), bucket_no bigint, count integer NOT NULL, PRIMARY KEY(key,bucket_no));

CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Append-only security record'; END;
$$;
CREATE TRIGGER immutable_transfer BEFORE UPDATE OR DELETE ON transfers FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER immutable_entry BEFORE UPDATE OR DELETE ON entries FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER immutable_audit BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE FUNCTION balanced_transfer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tid uuid; t transfers%ROWTYPE; n bigint; total numeric;
BEGIN
 IF TG_TABLE_NAME = 'transfers' THEN tid := NEW.id; ELSE tid := NEW.transfer_id; END IF;
 SELECT * INTO t FROM transfers WHERE id = tid;
 SELECT count(*), coalesce(sum(delta_minor),0) INTO n,total FROM entries WHERE transfer_id = tid;
 IF n <> 2 OR total <> 0 OR NOT EXISTS(SELECT 1 FROM entries WHERE transfer_id=tid AND wallet_id=t.source_id AND delta_minor=-t.amount_minor)
 OR NOT EXISTS(SELECT 1 FROM entries WHERE transfer_id=tid AND wallet_id=t.destination_id AND delta_minor=t.amount_minor) THEN
   RAISE EXCEPTION 'Unbalanced ledger transfer';
 END IF;
 IF (t.kind='transfer' AND NOT EXISTS(SELECT 1 FROM wallets WHERE id=t.source_id AND owner_id=t.actor_id AND NOT system))
 OR (t.kind='local_funding' AND NOT EXISTS(SELECT 1 FROM wallets WHERE id=t.source_id AND system))
 OR (t.kind='local_funding' AND NOT EXISTS(SELECT 1 FROM wallets WHERE id=t.destination_id AND owner_id=t.actor_id))
 OR NOT EXISTS(SELECT 1 FROM wallets WHERE id=t.destination_id AND NOT system) THEN
   RAISE EXCEPTION 'Invalid ledger ownership';
 END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER check_transfer AFTER INSERT ON transfers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION balanced_transfer();
CREATE CONSTRAINT TRIGGER check_entry AFTER INSERT ON entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION balanced_transfer();

CREATE FUNCTION consistent_balance() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE wid uuid; cached bigint; actual numeric;
BEGIN
 IF TG_TABLE_NAME = 'wallets' THEN wid := NEW.id; ELSE wid := NEW.wallet_id; END IF;
 SELECT balance_minor INTO cached FROM wallets WHERE id=wid;
 SELECT coalesce(sum(delta_minor),0) INTO actual FROM entries WHERE wallet_id=wid;
 IF cached <> actual THEN RAISE EXCEPTION 'Balance disagrees with ledger'; END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER check_wallet_balance AFTER INSERT OR UPDATE ON wallets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION consistent_balance();
CREATE CONSTRAINT TRIGGER check_entry_balance AFTER INSERT ON entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION consistent_balance();
