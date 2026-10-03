import os
from dataclasses import dataclass
from sqlalchemy.engine import make_url


@dataclass(frozen=True)
class Settings:
    database_url: str
    profile: str = "local"
    local_funding: bool = True
    auth_limit: int = 30
    transfer_limit: int = 120
    api_limit: int = 600
    session_minutes: int = 30
    max_body: int = 16384
    cors_origins: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "wallet-api", "testserver")

    def validate(self):
        url = make_url(self.database_url)
        if url.drivername != "postgresql+psycopg":
            raise ValueError("PostgreSQL with psycopg is required")
        if self.profile not in ("local", "production"):
            raise ValueError("Unknown profile")
        if "*" in self.cors_origins or "*" in self.allowed_hosts:
            raise ValueError("Wildcard origins/hosts are forbidden")
        if self.profile == "production":
            if self.local_funding:
                raise ValueError("Production forbids simulated funding")
            if not url.password or len(url.password) < 16 or url.query.get("sslmode") != "verify-full":
                raise ValueError("Production requires strong DB credentials and verified TLS")
            if any(not x.startswith("https://") for x in self.cors_origins):
                raise ValueError("Production CORS origins require HTTPS")
        if min(self.auth_limit, self.transfer_limit, self.api_limit, self.session_minutes, self.max_body) < 1:
            raise ValueError("Limits must be positive")
        return self

    @classmethod
    def from_env(cls):
        profile = os.getenv("WG_PROFILE", "local")
        return cls(
            database_url=os.environ["DATABASE_URL"],
            profile=profile,
            local_funding=os.getenv("WG_LOCAL_FUNDING", "true" if profile == "local" else "false") == "true",
            auth_limit=int(os.getenv("WG_AUTH_LIMIT", "30")),
            transfer_limit=int(os.getenv("WG_TRANSFER_LIMIT", "120")),
            api_limit=int(os.getenv("WG_API_LIMIT", "600")),
            cors_origins=tuple(filter(None, os.getenv("WG_CORS_ORIGINS", "").split(","))),
            allowed_hosts=tuple(os.getenv("WG_ALLOWED_HOSTS", "localhost,127.0.0.1,wallet-api").split(",")),
        ).validate()
