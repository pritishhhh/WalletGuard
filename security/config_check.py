"""Explicit Compose policy checks: Trivy does not currently parse Docker Compose."""
import json
from pathlib import Path
import yaml


def checks(config):
    failures = []
    services = config['services']
    api = services['wallet-api']
    if any(not str(port).startswith('127.0.0.1:') for port in api.get('ports',[])):
        failures.append(('WG-CONFIG-PORT','API publish must bind loopback'))
    if services['db'].get('ports'):
        failures.append(('WG-CONFIG-DB','Database must not be published'))
    for name in ['wallet-api','migrate']:
        service = services[name]
        if service.get('privileged') or not service.get('read_only') or 'ALL' not in service.get('cap_drop',[]):
            failures.append(('WG-CONFIG-HARDEN','API and migration containers need read-only filesystem and dropped capabilities'))
        if 'no-new-privileges:true' not in service.get('security_opt',[]):
            failures.append(('WG-CONFIG-PRIV','Privilege escalation must be disabled'))
    if not config['networks']['wallet-internal'].get('internal'):
        failures.append(('WG-CONFIG-NETWORK','Local test network must be internal'))
    return failures


def main():
    failures = checks(yaml.safe_load(Path('compose.yaml').read_text()))
    output = Path('reports/current/compose-checks.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps({'checks':7,'findings':[{'rule':rule,'component':'compose.yaml','severity':'high',
                                   'evidence':message,'fix':message,'owasp':['A02:2025']} for rule,message in failures]},indent=2))
    manifest_path = output.parent/'manifest.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {'runs':[]}
    manifest['runs'] = [r for r in manifest['runs'] if (r['tool'],r['scope'])!=('security-tests','compose')]
    manifest['runs'].append({'tool':'security-tests','scope':'compose','status':'success','exit_code':0 if not failures else 1,
                             'file':str(output)})
    manifest_path.write_text(json.dumps(manifest,indent=2))
    print(f'Compose policy: {len(failures)} findings')
    if failures:
        raise SystemExit(1)


if __name__=='__main__':
    main()
