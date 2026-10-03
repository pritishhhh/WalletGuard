"""Generate uncommitted local credentials, then optionally start Compose."""
import argparse
from pathlib import Path
import secrets
import subprocess
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--start',action='store_true')
args = parser.parse_args()
path = Path('.env')
if not path.exists():
    path.write_text('WG_DB_PASSWORD='+secrets.token_hex(24)+'\n',encoding='utf-8')
elif 'WG_DB_PASSWORD=' not in path.read_text():
    with path.open('a',encoding='utf-8') as output:
        output.write('WG_DB_PASSWORD='+secrets.token_hex(24)+'\n')
print('Local credentials ready in ignored .env file.')
if args.start:
    subprocess.run(['docker','compose','up','--build','-d','--wait','wallet-api'],check=True)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:8000/ready',timeout=5) as response:
        if response.status != 200:
            raise RuntimeError('Published local API did not become ready')
    print('Local API ready at http://127.0.0.1:8000/docs')
