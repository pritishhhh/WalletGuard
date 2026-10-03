import argparse
import json
import os
from pathlib import Path
from sqlalchemy import text
from .db import connect


def reconcile(engine):
    with engine.connect().execution_options(isolation_level="REPEATABLE READ") as db, db.begin():
        unbalanced = db.execute(text("""
          SELECT t.id FROM transfers t LEFT JOIN entries e ON e.transfer_id=t.id
          GROUP BY t.id HAVING count(e.id)<>2 OR coalesce(sum(e.delta_minor),0)<>0
          OR count(*) FILTER (WHERE e.wallet_id=t.source_id AND e.delta_minor=-t.amount_minor)<>1
          OR count(*) FILTER (WHERE e.wallet_id=t.destination_id AND e.delta_minor=t.amount_minor)<>1
        """)).scalars().all()
        balances = db.execute(text("""
          SELECT w.id FROM wallets w LEFT JOIN entries e ON e.wallet_id=w.id
          GROUP BY w.id HAVING w.balance_minor<>coalesce(sum(e.delta_minor),0)
          OR (NOT w.system AND w.balance_minor<0)
        """)).scalars().all()
        counts = db.execute(text("SELECT (SELECT count(*) FROM transfers), (SELECT count(*) FROM entries)")).one()
    return {"ok": not unbalanced and not balances, "transfers": counts[0], "entries": counts[1],
            "unbalanced_transfer_ids": list(map(str, unbalanced)), "mismatched_wallet_ids": list(map(str, balances))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["reconcile", "export-audit", "cleanup"])
    parser.add_argument("--output", default="reports/current/operations.json")
    args = parser.parse_args()
    engine, _ = connect(os.environ["DATABASE_URL"])
    if args.command == "reconcile":
        result = reconcile(engine)
    elif args.command == "cleanup":
        with engine.begin() as db:
            sessions = db.execute(text("DELETE FROM sessions WHERE expires_at<now()"))
            buckets = db.execute(text("DELETE FROM rate_buckets WHERE bucket_no<floor(extract(epoch FROM now())/60)-1440"))
            result = {"expired_sessions_removed": sessions.rowcount, "old_rate_buckets_removed": buckets.rowcount}
    else:
        with engine.connect() as db:
            result = [dict(row) for row in db.execute(text("SELECT * FROM audit ORDER BY id")).mappings()]
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(json.dumps(result if args.command != "export-audit" else {"audit_events": len(result)}, default=str))
    engine.dispose()
    if args.command == "reconcile" and not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
