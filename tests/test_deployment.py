import copy
from pathlib import Path
import yaml
from security.config_check import checks


def test_default_compose_and_unsafe_deployment_detection():
    config = yaml.safe_load(Path('compose.yaml').read_text())
    assert not checks(config)
    unsafe = copy.deepcopy(config)
    unsafe['services']['wallet-api']['ports'] = ['8000:8000']
    unsafe['services']['db']['ports'] = ['5432:5432']
    unsafe['services']['wallet-api']['privileged'] = True
    assert {r[0] for r in checks(unsafe)} >= {'WG-CONFIG-PORT','WG-CONFIG-DB','WG-CONFIG-HARDEN'}
