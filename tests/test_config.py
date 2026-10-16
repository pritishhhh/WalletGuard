from dataclasses import replace
import pytest
from walletguard.config import Settings
from sqlalchemy.engine import make_url


@pytest.mark.parametrize('change', [{'local_funding':True}, {'database_url':'postgresql+psycopg://u:short@db/wg'},
                                    {'cors_origins':('*',)}, {'allowed_hosts':('*',)},
                                    {'cors_origins':('http://example.org',)}])
def test_unsafe_production_configuration_rejected(change):
    safe = Settings(database_url='postgresql+psycopg://u:syntheticstrongpassword@db/wg?sslmode=verify-full',
                    profile='production',local_funding=False,allowed_hosts=('wallet.internal',))
    with pytest.raises(ValueError):
        replace(safe,**change).validate()


def test_safe_production_settings():
    assert Settings(database_url='postgresql+psycopg://u:syntheticstrongpassword@db/wg?sslmode=verify-full',
                    profile='production',local_funding=False).validate()


@pytest.mark.parametrize('scheme', ['postgres', 'postgresql'])
def test_vercel_provider_connection_uses_direct_driver_and_verified_tls(monkeypatch, scheme):
    monkeypatch.setenv('VERCEL', '1')
    monkeypatch.delenv('WG_PROFILE', raising=False)
    monkeypatch.delenv('WG_LOCAL_FUNDING', raising=False)
    monkeypatch.setenv('DATABASE_URL', f'{scheme}://u:syntheticstrongpassword@pool.example/wg?sslmode=require')
    monkeypatch.setenv('DATABASE_URL_UNPOOLED',
                       f'{scheme}://u:syntheticstrongpassword@direct.example/wg?sslmode=require&channel_binding=require')
    settings = Settings.from_env()
    url = make_url(settings.database_url)
    assert settings.profile == 'production' and not settings.local_funding
    assert url.drivername == 'postgresql+psycopg'
    assert url.host == 'direct.example'
    assert url.query['sslmode'] == 'verify-full'
    assert url.query['channel_binding'] == 'require'
    assert url.query['sslrootcert']


def test_vercel_does_not_accept_disabled_database_tls(monkeypatch):
    monkeypatch.setenv('VERCEL', '1')
    monkeypatch.setenv('WG_PROFILE', 'production')
    monkeypatch.setenv('WG_LOCAL_FUNDING', 'false')
    monkeypatch.delenv('DATABASE_URL_UNPOOLED', raising=False)
    monkeypatch.setenv('DATABASE_URL', 'postgresql://u:syntheticstrongpassword@db/wg?sslmode=disable')
    with pytest.raises(ValueError, match='verified TLS'):
        Settings.from_env()
