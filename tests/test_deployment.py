import copy
import runpy
import tomllib
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient
import yaml
from security.config_check import checks


def test_vercel_exports_real_api_and_serves_production_health(monkeypatch):
    monkeypatch.setenv('DATABASE_URL',
                       'postgresql+psycopg://u:syntheticstrongpassword@127.0.0.1:1/wg?sslmode=verify-full')
    monkeypatch.setenv('WG_PROFILE', 'production')
    monkeypatch.setenv('WG_LOCAL_FUNDING', 'false')
    monkeypatch.setenv('WG_ALLOWED_HOSTS', 'walletguard.example')
    config = tomllib.loads(Path('pyproject.toml').read_text())
    module, attribute = config['tool']['vercel']['entrypoint'].split(':')
    app = runpy.run_module(module)[attribute]
    assert isinstance(app, FastAPI)
    try:
        with TestClient(app, base_url='https://walletguard.example') as client:
            response = client.get('/health')
        assert response.status_code == 200
        assert response.json() == {'status': 'alive', 'simulation': True}
        assert response.headers['Strict-Transport-Security'].startswith('max-age=')
        assert app.state.settings.profile == 'production'
        assert not app.state.settings.local_funding
        assert {'/wallets', '/transfers', '/ready'} <= {route.path for route in app.routes}
        assert app.docs_url is None
    finally:
        app.state.engine.dispose()


def test_default_compose_and_unsafe_deployment_detection():
    config = yaml.safe_load(Path('compose.yaml').read_text())
    assert not checks(config)
    unsafe = copy.deepcopy(config)
    unsafe['services']['wallet-api']['ports'] = ['8000:8000']
    unsafe['services']['db']['ports'] = ['5432:5432']
    unsafe['services']['wallet-api']['privileged'] = True
    assert {r[0] for r in checks(unsafe)} >= {'WG-CONFIG-PORT','WG-CONFIG-DB','WG-CONFIG-HARDEN'}


def test_database_and_scanner_cannot_gain_external_network():
    config = yaml.safe_load(Path('compose.yaml').read_text())
    for name in ['db','migrate','zap']:
        unsafe = copy.deepcopy(config)
        unsafe['services'][name]['networks'].append('wallet-host')
        assert 'WG-CONFIG-ISOLATION' in {r[0] for r in checks(unsafe)}
