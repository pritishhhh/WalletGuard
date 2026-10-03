import os
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from walletguard.app import create_app
from walletguard.config import Settings


@pytest.fixture(scope="session")
def database_url():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.fail("Set TEST_DATABASE_URL to a disposable PostgreSQL database ending in _test")
    if not make_url(url).database.endswith("_test"):
        pytest.fail("Refusing to reset a database whose name does not end in _test")
    old = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    command.upgrade(Config("alembic.ini"), "head")
    if old:
        os.environ["DATABASE_URL"] = old
    else:
        os.environ.pop("DATABASE_URL", None)
    return url


@pytest.fixture
def app(database_url):
    engine = create_engine(database_url)
    with engine.begin() as db:
        db.execute(text("TRUNCATE entries,transfers,audit,sessions,wallets,users,rate_buckets RESTART IDENTITY CASCADE"))
        db.execute(text("INSERT INTO wallets VALUES ('00000000-0000-0000-0000-000000000001',NULL,'SIMULATED TREASURY','INR',0,true)"))
    engine.dispose()
    app = create_app(Settings(database_url=database_url, auth_limit=1000, api_limit=10000, transfer_limit=1000))
    yield app
    app.state.engine.dispose()


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


@pytest.fixture
def actors(client):
    result = []
    for username in ["alice", "bob", "charlie"]:
        credentials = {"username": username, "password": "Synthetic passphrase 123!"}
        registration = client.post("/auth/register", json=credentials)
        assert registration.status_code == 201, registration.text
        token = client.post("/auth/login", json=credentials)
        assert token.status_code == 200, token.text
        headers = {"Authorization": "Bearer " + token.json()["access_token"]}
        wallet = client.post("/wallets", json={"label": username}, headers=headers)
        assert wallet.status_code == 201, wallet.text
        result.append({"id": registration.json()["id"], "wallet": wallet.json()["id"], "headers": headers})
    return result


def fund(client, actor, amount=1000, key="fund-test-001"):
    response = client.post(f"/wallets/{actor['wallet']}/fund", json={"amount_minor": amount},
                           headers={**actor['headers'], "Idempotency-Key": key})
    assert response.status_code == 200, response.text
    return response.json()


def transfer(client, actor, destination, amount=100, key="transfer-test-001"):
    return client.post("/transfers", json={"source_id": actor['wallet'], "destination_id": destination,
                       "amount_minor": amount}, headers={**actor['headers'], "Idempotency-Key": key})
