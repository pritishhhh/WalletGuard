from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from walletguard.app import create_app
from walletguard.cli import reconcile
from walletguard.db import Audit, Entry, SessionToken, User
from conftest import fund, transfer

pytestmark = pytest.mark.integration


def test_successful_transfer_balanced(client, actors, app):
    alice, bob, _ = actors
    fund(client, alice)
    response = transfer(client, alice, bob['wallet'])
    assert response.status_code == 200, response.text
    assert client.get('/wallets/'+alice['wallet'], headers=alice['headers']).json()['balance_minor'] == 900
    assert client.get('/wallets/'+bob['wallet'], headers=bob['headers']).json()['balance_minor'] == 100
    with app.state.sessions() as db:
        entries = db.scalars(select(Entry).where(Entry.transfer_id == uuid.UUID(response.json()['id']))).all()
        assert sorted(e.delta_minor for e in entries) == [-100,100]
    assert reconcile(app.state.engine) == {'ok': True, 'transfers': 2, 'entries': 4,
                                          'unbalanced_transfer_ids': [], 'mismatched_wallet_ids': []}


def test_insufficient_no_partial_ledger(client, actors, app):
    alice, bob, _ = actors
    response = transfer(client, alice, bob['wallet'])
    assert response.status_code == 409
    assert reconcile(app.state.engine)['transfers'] == 0


@pytest.mark.parametrize('amount', [0,-1,1.5,True,'100',1000000001,None])
def test_invalid_amounts(client, actors, amount):
    assert transfer(client, actors[0], actors[1]['wallet'], amount).status_code == 422


def test_idempotency_retry_conflict_and_namespace(client, actors, app):
    alice, bob, _ = actors
    fund(client, alice)
    first = transfer(client, alice, bob['wallet'])
    assert transfer(client, alice, bob['wallet']).json() == first.json()
    assert transfer(client, alice, bob['wallet'], 101).status_code == 409
    assert transfer(client, bob, alice['wallet'], 10).status_code == 200
    assert reconcile(app.state.engine)['transfers'] == 3
    assert client.post('/wallets/'+alice['wallet']+'/fund', json={'amount_minor':1000},
                       headers={**alice['headers'],'Idempotency-Key':'fund-test-001'}).status_code == 200


@pytest.mark.stress
def test_parallel_no_overspend(client, actors, app):
    alice, bob, _ = actors
    fund(client, alice, 1000)
    with ThreadPoolExecutor(max_workers=16) as pool:
        responses = list(pool.map(lambda n: transfer(client, alice, bob['wallet'], 30, f'parallel-{n:04}'), range(64)))
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 33, statuses
    assert statuses.count(409) == 31, statuses
    assert client.get('/wallets/'+alice['wallet'], headers=alice['headers']).json()['balance_minor'] == 10
    assert client.get('/wallets/'+bob['wallet'], headers=bob['headers']).json()['balance_minor'] == 990
    assert reconcile(app.state.engine)['ok']


@pytest.mark.stress
def test_parallel_replay_and_opposite_direction(client, actors, app):
    alice, bob, _ = actors
    fund(client, alice)
    fund(client, bob)
    with ThreadPoolExecutor(max_workers=8) as pool:
        repeated = list(pool.map(lambda _: transfer(client, alice, bob['wallet'], 10, 'same-key-0001'), range(16)))
        directions = list(pool.map(lambda n: transfer(client, actors[n%2], actors[1-n%2]['wallet'], 1,
                                                      f'reverse-{n:04}'), range(32)))
    assert all(r.status_code == 200 for r in repeated+directions)
    assert len({r.json()['id'] for r in repeated}) == 1
    assert reconcile(app.state.engine)['transfers'] == 35


@pytest.mark.parametrize('path', ['detail','history','fund','transfer'])
def test_cross_user_wallet_endpoints(client, actors, path):
    alice, bob, _ = actors
    if path == 'detail':
        response = client.get('/wallets/'+alice['wallet'], headers=bob['headers'])
    elif path == 'history':
        response = client.get('/wallets/'+alice['wallet']+'/transactions', headers=bob['headers'])
    elif path == 'fund':
        response = client.post('/wallets/'+alice['wallet']+'/fund', json={'amount_minor':100},
                               headers={**bob['headers'],'Idempotency-Key':'cross-fund-001'})
    else:
        response = transfer(client, {**alice,'headers':bob['headers']}, bob['wallet'])
    assert response.status_code == 404
    listed = client.get('/wallets', headers=bob['headers']).json()['items']
    assert {w['id'] for w in listed} == {bob['wallet']}


def test_transaction_owner_sender_recipient_and_outsider(client, actors):
    alice, bob, charlie = actors
    funding = fund(client, alice)
    moved = transfer(client, alice, bob['wallet']).json()
    for actor in (alice,bob):
        assert client.get('/transactions/'+moved['id'], headers=actor['headers']).status_code == 200
    assert client.get('/transactions/'+moved['id'], headers=charlie['headers']).status_code == 404
    assert client.get('/transactions/'+funding['id'], headers=bob['headers']).status_code == 404


@pytest.mark.parametrize('field,value', [('balance_minor',999),('owner_id',str(uuid.UUID(int=2))),
                                         ('role','admin'),('system',True),('entries',[])])
def test_wallet_field_tampering(client, actors, field, value):
    assert client.post('/wallets', json={'label':'tamper',field:value}, headers=actors[0]['headers']).status_code == 422


def test_role_and_transfer_field_tampering(client, actors):
    assert client.post('/auth/register', json={'username':'admin','password':'Synthetic passphrase 123!',
                                             'role':'admin'}).status_code == 422
    assert client.post('/transfers', json={'source_id':actors[0]['wallet'],'destination_id':actors[1]['wallet'],
                                          'amount_minor':100,'balance_minor':10000},
                       headers={**actors[0]['headers'],'Idempotency-Key':'tamper-field-001'}).status_code == 422


def test_auth_failures_expiry_logout_and_digest(client, actors, app):
    assert client.get('/wallets').status_code == 401
    assert client.get('/wallets',headers={'Authorization':'Bearer forged'}).status_code == 401
    failures = [client.post('/auth/login',json={'username':name,'password':'Wrong passphrase 123!'})
                for name in ['alice','unknown']]
    assert [r.status_code for r in failures] == [401,401]
    assert failures[0].json()['error'] == failures[1].json()['error']
    token = actors[0]['headers']['Authorization'].split()[1]
    with app.state.sessions() as db, db.begin():
        session = db.get(SessionToken,hashlib.sha256(token.encode()).hexdigest())
        assert session.digest != token
        session.expires_at = datetime.now(timezone.utc)-timedelta(minutes=1)
        assert db.scalar(select(User).where(User.username=='alice')).password_hash.startswith('$argon2id$')
    assert client.get('/auth/me',headers=actors[0]['headers']).status_code == 401
    assert client.post('/auth/logout',headers=actors[1]['headers']).status_code == 204
    assert client.get('/auth/me',headers=actors[1]['headers']).status_code == 401


def test_auth_and_transfer_rate_limits_persist(client, actors, app):
    fund(client, actors[0])
    app.state.settings = replace(app.state.settings, auth_limit=2, transfer_limit=1)
    # Existing counters already exceed reduced limits; recreating the API must not reset them.
    assert client.post('/auth/login',json={'username':'alice','password':'Wrong passphrase 123!'}).status_code == 429
    assert transfer(client,actors[0],actors[1]['wallet']).status_code == 429
    restarted = create_app(app.state.settings)
    with TestClient(restarted) as fresh:
        assert fresh.post('/auth/login',json={'username':'alice','password':'Wrong passphrase 123!'}).status_code == 429
    restarted.state.engine.dispose()


def test_request_limits_errors_headers_and_audit(client, app):
    response = client.post('/auth/register',content='a'*17000,headers={'Content-Type':'application/json',
                                                                    'X-Request-ID':'request-001'})
    assert response.status_code == 413
    assert response.headers['X-Request-ID'] == 'request-001'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.json()['error']['code'] == 'request_too_large'
    chunked = client.post('/auth/register',content=iter([b'a'*9000,b'b'*9000]))
    assert chunked.status_code == 413
    failure = client.post('/auth/login',json={'username':'bad','password':'short'})
    assert failure.status_code == 422
    assert 'short' not in failure.text
    with app.state.sessions() as db:
        assert db.scalar(select(Audit).where(Audit.request_id=='request-001')).outcome == 'denied'
    for invalid in [client.get('/missing-route'),client.get('/health',headers={'Host':'untrusted.example'})]:
        assert invalid.status_code in (400,404)
        assert set(invalid.json()) == {'error','request_id'}


def test_history_pagination_and_restart_persistence(client, actors, app):
    alice,bob,_ = actors
    fund(client,alice)
    transfer(client,alice,bob['wallet'])
    url = '/wallets/'+alice['wallet']+'/transactions'
    first = client.get(url+'?limit=1',headers=alice['headers']).json()
    second = client.get(url+'?limit=1&offset=1',headers=alice['headers']).json()
    assert first['items'][0]['id'] != second['items'][0]['id']
    assert client.get(url+'?limit=101',headers=alice['headers']).status_code == 422
    restarted = create_app(app.state.settings)
    with TestClient(restarted) as fresh:
        assert fresh.get('/ready').status_code == 200
        assert fresh.get('/wallets/'+alice['wallet'],headers=alice['headers']).json()['balance_minor'] == 900
    restarted.state.engine.dispose()


def test_ledger_audit_and_balance_database_guards(client, actors, app):
    funding = fund(client,actors[0])
    for sql in ["UPDATE entries SET delta_minor=999", "DELETE FROM transfers", "DELETE FROM audit",
                "UPDATE wallets SET balance_minor=-1 WHERE NOT system", "UPDATE wallets SET balance_minor=999 WHERE NOT system"]:
        with pytest.raises(DBAPIError), app.state.engine.begin() as db:
            db.execute(text(sql))
    with pytest.raises(DBAPIError), app.state.engine.begin() as db:
        db.execute(text("""INSERT INTO transfers(id,actor_id,source_id,destination_id,amount_minor,kind,idempotency_key,request_hash)
          SELECT :id,actor_id,source_id,destination_id,100,'local_funding','unbalanced-001',request_hash FROM transfers WHERE id=:existing"""),
                   {'id':uuid.uuid4(),'existing':uuid.UUID(funding['id'])})
    assert reconcile(app.state.engine)['ok']


def test_self_transfer_missing_destination_and_key(client, actors):
    alice = actors[0]
    assert transfer(client,alice,alice['wallet']).status_code == 422
    assert transfer(client,alice,str(uuid.UUID(int=42))).status_code == 404
    assert client.post('/transfers',json={'source_id':alice['wallet'],'destination_id':actors[1]['wallet'],'amount_minor':1},
                       headers=alice['headers']).status_code == 422


def test_bound_sql_injection_and_secure_cors(client, actors):
    response = client.get("/wallets/' OR 1=1--",headers=actors[0]['headers'])
    assert response.status_code == 422
    response = client.options('/wallets',headers={'Origin':'https://untrusted.example','Access-Control-Request-Method':'POST'})
    assert 'access-control-allow-origin' not in response.headers


def test_funding_disabled_profile(client, actors, app):
    disabled = create_app(replace(app.state.settings,local_funding=False))
    with TestClient(disabled) as fresh:
        assert fresh.post('/wallets/'+actors[0]['wallet']+'/fund',json={'amount_minor':100},
                          headers={**actors[0]['headers'],'Idempotency-Key':'disabled-001'}).status_code == 404
    disabled.state.engine.dispose()


def test_structured_logs_exclude_credentials(client, caplog):
    credentials = {'username':'logger_user','password':'Never log this passphrase!'}
    client.post('/auth/register',json=credentials,headers={'X-Request-ID':'log-test-001'})
    response = client.post('/auth/login',json=credentials)
    assert response.status_code == 200
    token = response.json()['access_token']
    messages = '\n'.join(r.getMessage() for r in caplog.records)
    assert 'log-test-001' in messages and 'http_request' in messages
    assert credentials['password'] not in messages and token not in messages
