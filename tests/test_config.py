from dataclasses import replace
import pytest
from walletguard.config import Settings


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
