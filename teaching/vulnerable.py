"""Intentionally vulnerable in-process fixture. No default server entry point."""
import sqlite3
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware


def create_vulnerable_fixture():
    app = FastAPI(debug=True)
    app.add_middleware(CORSMiddleware,allow_origins=['*'])

    @app.get('/wallets/{wallet_id}')
    def wallet(wallet_id: int):
        # Deliberately no authenticated ownership check: regression exercise only.
        return {'id':wallet_id,'owner':'alice','balance_minor':1000}

    @app.get('/search')
    def search(owner: str):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE wallets(id integer, owner text)')
            db.execute("INSERT INTO wallets VALUES(1,'alice'),(2,'bob')")
            return db.execute("SELECT id,owner FROM wallets WHERE owner='" + owner + "'").fetchall()
    return app
