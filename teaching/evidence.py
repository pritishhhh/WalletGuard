"""Generate actual detection evidence from the isolated teaching fixture."""
import json
from pathlib import Path
from fastapi.testclient import TestClient
from .vulnerable import create_vulnerable_fixture


def detect():
    with TestClient(create_vulnerable_fixture()) as client:
        bola = client.get('/wallets/1')
        injection = client.get('/search',params={'owner':"alice' OR 1=1--"})
        cors = client.options('/wallets/1',headers={'Origin':'https://untrusted.example','Access-Control-Request-Method':'GET'})
    assert bola.status_code == 200 and bola.json()['owner']=='alice'
    assert len(injection.json()) == 2
    assert cors.headers['access-control-allow-origin']=='*'
    return {'fixture_only':True,'findings':[
        {'rule':'WG-BOLA-001','component':'teaching/vulnerable.py:/wallets/{id}','severity':'high',
         'evidence':'Unauthenticated GET /wallets/1 returned HTTP 200 with Alice balance 1000.',
         'fix':'Require bearer identity and owner predicate; secure API test_cross_user_wallet_endpoints returns 404.',
         'cwe':['CWE-639'],'owasp':['API1:2023','A01:2025']},
        {'rule':'WG-SQL-001','component':'teaching/vulnerable.py:/search','severity':'high',
         'evidence':"owner=alice' OR 1=1-- returned both Alice and Bob rows (2).",
         'fix':'Use bound SQL and validated UUIDs; secure API injection regression returns 422.',
         'cwe':['CWE-89'],'owasp':['A05:2025']},
        {'rule':'WG-CORS-001','component':'teaching/vulnerable.py','severity':'medium',
         'evidence':'Untrusted Origin preflight returned access-control-allow-origin: *.',
         'fix':'Default to no permitted cross-origin clients; secure API preflight omits allow-origin.',
         'cwe':['CWE-942'],'owasp':['A02:2025']}]}


if __name__=='__main__':
    path = Path('reports/teaching/security-tests.json')
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(detect(),indent=2),encoding='utf-8')
    print('Three intentional teaching weaknesses detected; evidence written.')
