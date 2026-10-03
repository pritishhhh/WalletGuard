import hashlib
import json
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from .config import Settings
from .db import Entry, SessionToken, Transfer, User, Wallet, connect
from .schemas import Credentials, FundingCreate, TransferCreate, WalletCreate
from .service import TREASURY, audit, move, owned, transfer_view, wallet_view

log = logging.getLogger("walletguard")
log.setLevel(logging.INFO)
if not log.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
dummy_hash = hasher.hash(secrets.token_urlsafe(32))
bearer = HTTPBearer(auto_error=False)


class BodyLimit:
    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.limit:
                response = JSONResponse({"error": {"code": "request_too_large", "message": "Request too large"},
                                         "request_id": scope.get("state", {}).get("request_id")}, status_code=413)
                return await response(scope, receive, send)
            chunks.append(message)
            if not message.get("more_body", False):
                break
        async def replay():
            return chunks.pop(0) if chunks else await receive()
        await self.app(scope, replay, send)


def create_app(settings=None):
    settings = (settings or Settings.from_env()).validate()
    app = FastAPI(title="WalletGuard", version="1.0.0", description="Synthetic wallet. No real funds.",
                  docs_url="/docs" if settings.profile == "local" else None, redoc_url=None)
    app.state.settings = settings
    app.state.engine, app.state.sessions = connect(settings.database_url)
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_credentials=False,
                       allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type", "Idempotency-Key"])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.add_middleware(BodyLimit, limit=settings.max_body)

    def database():
        with app.state.sessions() as db, db.begin():
            yield db
    DB = Annotated[object, Depends(database, scope="function")]

    def throttle(scope, identity, maximum):
        key = hashlib.sha256(f"{scope}:{identity}".encode()).hexdigest()
        with app.state.engine.begin() as connection:
            count = connection.scalar(text("""
                INSERT INTO rate_buckets(key, bucket_no, count)
                VALUES (:key, floor(extract(epoch FROM now()) / 60)::bigint, 1)
                ON CONFLICT (key, bucket_no) DO UPDATE SET count = rate_buckets.count + 1
                RETURNING count
            """), {"key": key})
        if count > maximum:
            raise HTTPException(429, "Rate limit exceeded", headers={"Retry-After": "60"})

    def current_user(request: Request, db: DB,
                     credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        if not credentials or len(credentials.credentials) > 200:
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
        digest = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        user = db.scalar(select(User).join(SessionToken, SessionToken.user_id == User.id)
                         .where(SessionToken.digest == digest, SessionToken.expires_at > func.now()))
        if user is None:
            raise HTTPException(401, "Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
        request.state.actor_id = user.id
        request.state.session_digest = digest
        return user
    Actor = Annotated[User, Depends(current_user)]

    def idempotency(value: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128,
                                                 pattern=r"^[a-zA-Z0-9._-]+$")]):
        return value
    Key = Annotated[str, Depends(idempotency)]

    def error_response(request, status, code, message, headers=None):
        return JSONResponse({"error": {"code": code, "message": message},
                             "request_id": getattr(request.state, "request_id", None)}, status_code=status,
                            headers=headers)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        return error_response(request, exc.status_code, f"http_{exc.status_code}", exc.detail, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return error_response(request, 422, "validation_error", "Request failed strict validation")

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        return error_response(request, 503, "database_unavailable", "Database operation unavailable; retry safely")

    @app.middleware("http")
    async def security_envelope(request, call_next):
        candidate = request.headers.get("X-Request-ID", "")
        request.state.request_id = candidate if re.fullmatch(r"[a-zA-Z0-9._-]{1,64}", candidate) else str(uuid.uuid4())
        try:
            if request.url.path not in ("/health", "/ready"):
                throttle("api", request.client.host if request.client else "unknown", app.state.settings.api_limit)
            response = await call_next(request)
            if response.status_code == 400 and response.headers.get("content-type", "").startswith("text/plain"):
                response = error_response(request, 400, "http_400", "Invalid request host")
        except HTTPException as exc:
            response = error_response(request, exc.status_code, f"http_{exc.status_code}", exc.detail, exc.headers)
        except Exception:
            response = error_response(request, 503, "service_unavailable", "Service temporarily unavailable")
        response.headers.update({"X-Request-ID": request.state.request_id, "X-Content-Type-Options": "nosniff",
                                 "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                                 "Cache-Control": "no-store", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"})
        if request.url.path != "/docs":
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if settings.profile == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        route = request.scope.get("route")
        route_name = route.path if route else "unmatched"
        if response.status_code >= 400:
            try:
                with app.state.sessions() as db, db.begin():
                    audit(db, request, f"http_denied_{response.status_code}",
                          getattr(request.state, "actor_id", None), outcome="denied")
            except SQLAlchemyError:
                log.error(json.dumps({"event": "audit_write_failed", "request_id": request.state.request_id}))
        log.info(json.dumps({"event": "http_request", "request_id": request.state.request_id,
                             "method": request.method, "route": route_name, "status": response.status_code}))
        return response

    @app.get("/health", tags=["operations"])
    def health():
        return {"status": "alive", "simulation": True}

    @app.get("/ready", tags=["operations"])
    def ready(db: DB):
        if db.scalar(text("SELECT version_num FROM alembic_version")) != "0001":
            raise HTTPException(503, "Database migration required")
        return {"status": "ready"}

    @app.post("/auth/register", status_code=201, tags=["authentication"])
    def register(data: Credentials, request: Request, db: DB):
        throttle("auth_ip", request.client.host, app.state.settings.auth_limit)
        user = User(username=data.username, password_hash=hasher.hash(data.password.get_secret_value()))
        try:
            with db.begin_nested():
                db.add(user)
                db.flush()
        except IntegrityError:
            raise HTTPException(409, "Registration unavailable") from None
        audit(db, request, "register", user.id, user.id)
        return {"id": str(user.id), "username": user.username, "role": "user"}

    @app.post("/auth/login", tags=["authentication"])
    def login(data: Credentials, request: Request, db: DB):
        throttle("auth_ip", request.client.host, app.state.settings.auth_limit)
        throttle("auth_account", data.username, app.state.settings.auth_limit)
        user = db.scalar(select(User).where(User.username == data.username))
        try:
            hasher.verify(user.password_hash if user else dummy_hash, data.password.get_secret_value())
        except (VerificationError, InvalidHashError):
            raise HTTPException(401, "Invalid credentials") from None
        if user is None:
            raise HTTPException(401, "Invalid credentials")
        if hasher.check_needs_rehash(user.password_hash):
            user.password_hash = hasher.hash(data.password.get_secret_value())
        token = secrets.token_urlsafe(32)
        expiry = datetime.now(timezone.utc) + timedelta(minutes=settings.session_minutes)
        db.add(SessionToken(digest=hashlib.sha256(token.encode()).hexdigest(), user_id=user.id, expires_at=expiry))
        audit(db, request, "login", user.id)
        return {"access_token": token, "token_type": "bearer", "expires_at": expiry.isoformat()}

    @app.post("/auth/logout", status_code=204, tags=["authentication"])
    def logout(request: Request, db: DB, user: Actor):
        db.execute(delete(SessionToken).where(SessionToken.digest == request.state.session_digest))
        audit(db, request, "logout", user.id)

    @app.get("/auth/me", tags=["authentication"])
    def me(user: Actor):
        return {"id": str(user.id), "username": user.username, "role": user.role}

    @app.post("/wallets", status_code=201, tags=["wallets"])
    def create_wallet(data: WalletCreate, request: Request, db: DB, user: Actor):
        db.scalar(select(User).where(User.id == user.id).with_for_update())
        if db.scalar(select(func.count()).select_from(Wallet).where(Wallet.owner_id == user.id)) >= 20:
            raise HTTPException(409, "Wallet limit reached")
        wallet = Wallet(owner_id=user.id, label=data.label, currency=data.currency)
        db.add(wallet)
        db.flush()
        audit(db, request, "wallet_create", user.id, wallet.id)
        return wallet_view(wallet)

    @app.get("/wallets", tags=["wallets"])
    def list_wallets(db: DB, user: Actor):
        return {"items": [wallet_view(w) for w in db.scalars(select(Wallet).where(Wallet.owner_id == user.id)
                                                             .order_by(Wallet.id))]}

    @app.get("/wallets/{wallet_id}", tags=["wallets"])
    def get_wallet(wallet_id: uuid.UUID, db: DB, user: Actor):
        return wallet_view(owned(db, wallet_id, user.id))

    @app.get("/wallets/{wallet_id}/transactions", tags=["wallets"])
    def history(wallet_id: uuid.UUID, db: DB, user: Actor,
                limit: Annotated[int, Query(ge=1, le=100)] = 20,
                offset: Annotated[int, Query(ge=0, le=10000)] = 0):
        owned(db, wallet_id, user.id)
        rows = db.scalars(select(Transfer).join(Entry, Entry.transfer_id == Transfer.id)
                          .where(Entry.wallet_id == wallet_id).order_by(Transfer.created_at.desc(), Transfer.id.desc())
                          .limit(limit).offset(offset)).all()
        return {"items": [transfer_view(t) for t in rows], "limit": limit, "offset": offset,
                "next_offset": offset + limit if len(rows) == limit else None}

    @app.get("/transactions/{transaction_id}", tags=["transfers"])
    def get_transaction(transaction_id: uuid.UUID, db: DB, user: Actor):
        row = db.scalar(select(Transfer).join(Entry, Entry.transfer_id == Transfer.id)
                        .join(Wallet, Wallet.id == Entry.wallet_id)
                        .where(Transfer.id == transaction_id, Wallet.owner_id == user.id).limit(1))
        if not row:
            raise HTTPException(404, "Resource not found")
        return transfer_view(row)

    @app.post("/transfers", tags=["transfers"])
    def transfer(data: TransferCreate, request: Request, db: DB, user: Actor, key: Key):
        throttle("movement", user.id, app.state.settings.transfer_limit)
        return move(db, request, user, data.source_id, data.destination_id, data.amount_minor, key)

    @app.post("/wallets/{wallet_id}/fund", tags=["local simulation"],
              description="LOCAL ONLY: simulated treasury funding; no payment integration.")
    def fund(wallet_id: uuid.UUID, data: FundingCreate, request: Request, db: DB, user: Actor, key: Key):
        if settings.profile != "local" or not settings.local_funding:
            raise HTTPException(404, "Resource not found")
        throttle("movement", user.id, app.state.settings.transfer_limit)
        return move(db, request, user, TREASURY, wallet_id, data.amount_minor, key, "local_funding")
    return app
