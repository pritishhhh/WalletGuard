"""ASGI application exported for Vercel's FastAPI runtime."""

from walletguard.app import create_app

app = create_app()
