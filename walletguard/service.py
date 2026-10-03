import hashlib
import json
import uuid
from fastapi import HTTPException
from sqlalchemy import select, text
from .db import Audit, Entry, Transfer, Wallet

TREASURY = uuid.UUID("00000000-0000-0000-0000-000000000001")


def audit(db, request, action, actor=None, object_id=None, outcome="success"):
    db.add(Audit(actor_id=actor, action=action, object_id=str(object_id) if object_id else None,
                 request_id=request.state.request_id, outcome=outcome))


def owned(db, wallet_id, user_id):
    wallet = db.scalar(select(Wallet).where(Wallet.id == wallet_id, Wallet.owner_id == user_id,
                                          Wallet.system.is_(False)))
    if wallet is None:
        raise HTTPException(404, "Resource not found")
    return wallet


def wallet_view(wallet):
    return {"id": str(wallet.id), "label": wallet.label, "currency": wallet.currency,
            "balance_minor": wallet.balance_minor}


def transfer_view(transfer):
    return {"id": str(transfer.id), "source_id": str(transfer.source_id),
            "destination_id": str(transfer.destination_id), "amount_minor": transfer.amount_minor,
            "kind": transfer.kind, "created_at": transfer.created_at.isoformat()}


def move(db, request, user, source_id, destination_id, amount, key, kind="transfer"):
    if source_id == destination_id:
        raise HTTPException(422, "Source and destination must differ")
    if kind == "transfer":
        owned(db, source_id, user.id)
    else:
        owned(db, destination_id, user.id)
    fingerprint = hashlib.sha256(json.dumps([kind, str(source_id), str(destination_id), amount]).encode()).hexdigest()
    lock = int.from_bytes(hashlib.sha256(f"{user.id}:{key}".encode()).digest()[:8], "big", signed=True)
    # This lock is database-wide, transaction-scoped, and works across processes/replicas.
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock})
    previous = db.scalar(select(Transfer).where(Transfer.actor_id == user.id, Transfer.idempotency_key == key))
    if previous:
        if previous.request_hash != fingerprint:
            raise HTTPException(409, "Idempotency key already used with different content")
        audit(db, request, "idempotent_replay", user.id, previous.id)
        return transfer_view(previous)
    # Deterministic order prevents opposite-direction transfers from deadlocking.
    wallets = db.scalars(select(Wallet).where(Wallet.id.in_([source_id, destination_id]))
                         .order_by(Wallet.id).with_for_update().execution_options(populate_existing=True)).all()
    by_id = {w.id: w for w in wallets}
    if len(by_id) != 2 or by_id[destination_id].system:
        raise HTTPException(404, "Resource not found")
    source, destination = by_id[source_id], by_id[destination_id]
    if not source.system and source.balance_minor < amount:
        raise HTTPException(409, "Insufficient funds")
    if destination.balance_minor + amount > 9_000_000_000_000_000:
        raise HTTPException(409, "Wallet balance limit exceeded")
    source.balance_minor -= amount
    destination.balance_minor += amount
    transfer = Transfer(actor_id=user.id, source_id=source_id, destination_id=destination_id,
                        amount_minor=amount, kind=kind, idempotency_key=key, request_hash=fingerprint)
    db.add(transfer)
    db.flush()
    db.add_all([Entry(transfer_id=transfer.id, wallet_id=source_id, delta_minor=-amount),
                Entry(transfer_id=transfer.id, wallet_id=destination_id, delta_minor=amount)])
    audit(db, request, kind, user.id, transfer.id)
    db.flush()
    return transfer_view(transfer)
