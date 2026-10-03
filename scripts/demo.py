"""Synthetic wallet workflow plus optional full local checks."""
import argparse
from pathlib import Path
import subprocess
import sys
import webbrowser
import httpx
from security.dast import preflight, seed

parser = argparse.ArgumentParser()
parser.add_argument('--checks',action='store_true',help='Run tests, static scanners, reconciliation, and passive ZAP')
parser.add_argument('--open-report',action='store_true')
args = parser.parse_args()
target = preflight({'target':'http://127.0.0.1:8000','allowlist':['http://127.0.0.1:8000'],'authorization':'local synthetic demo'})
with httpx.Client(base_url=target,timeout=15,trust_env=False) as client:
    token,wallet,denials = seed(client)
    balance = client.get('/wallets/'+wallet,headers={'Authorization':'Bearer '+token}).json()['balance_minor']
    print('Created two users and wallets; funded 1,000 synthetic minor units; transferred 100; sender balance:',balance)
    print('Cross-user checks:',denials)
if args.checks:
    for command in [[sys.executable,'-m','pytest','-q','--junitxml=reports/current/pytest.xml'],
                    [sys.executable,'-m','walletguard.cli','reconcile'],
                    [sys.executable,'-m','security.config_check'],
                    [sys.executable,'-m','security.scan','static'],
                    [sys.executable,'-m','security.dast','--seed-wallet'],
                    [sys.executable,'-m','security.findings','--manifest','reports/current/manifest.json','--gate']]:
        subprocess.run(command,check=True)
if args.open_report:
    path = Path('reports/current/findings.html')
    if not path.exists():
        path = Path('reports/sample/findings.html')
    webbrowser.open(path.resolve().as_uri())
