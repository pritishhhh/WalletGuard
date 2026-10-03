# Executable API workflow

With the API running and httpx installed, save or run this Python snippet from the repository. It prints balances and statuses, never bearer tokens. Passwords here are local synthetic examples only.

```python
import secrets
import httpx

suffix = secrets.token_hex(4)
with httpx.Client(base_url='http://127.0.0.1:8000',trust_env=False) as api:
    wallets, headers = [], []
    for name in ['alice_','bob_']:
        credentials = {'username':name+suffix,'password':secrets.token_urlsafe(24)}
        api.post('/auth/register',json=credentials).raise_for_status()
        login = api.post('/auth/login',json=credentials)
        login.raise_for_status()
        auth = {'Authorization':'Bearer '+login.json()['access_token']}
        wallet = api.post('/wallets',json={'label':name},headers=auth)
        wallet.raise_for_status()
        headers.append(auth)
        wallets.append(wallet.json()['id'])
    api.post(f'/wallets/{wallets[0]}/fund',json={'amount_minor':1000},
             headers={**headers[0],'Idempotency-Key':'fund-'+suffix}).raise_for_status()
    transfer = {'source_id':wallets[0],'destination_id':wallets[1],'amount_minor':100}
    auth = {**headers[0],'Idempotency-Key':'transfer-'+suffix}
    first = api.post('/transfers',json=transfer,headers=auth)
    first.raise_for_status()
    assert api.post('/transfers',json=transfer,headers=auth).json()==first.json()
    assert api.post('/transfers',json={**transfer,'amount_minor':101},headers=auth).status_code==409
    assert api.get(f'/wallets/{wallets[0]}',headers=headers[1]).status_code==404
    print(api.get(f'/wallets/{wallets[0]}',headers=headers[0]).json())
    print(api.get(f'/wallets/{wallets[1]}/transactions?limit=10&offset=0',headers=headers[1]).json())
```

GET /health is process liveness; GET /ready checks the migration version in PostgreSQL. Invalid request fields return 422, expired/missing sessions 401, unavailable/non-owned objects 404, insufficient funds/conflicting keys 409, body limits 413, rate limits 429 with Retry-After, and database failures 503. Errors share an error code/message and request ID. Same-key/content successful retries are 200 with the same transfer ID and timestamp. A failed money movement leaves no ledger rows and may be retried using the same key.
