"""Preflight exact authorized origins, verify identity, run ZAP Automation Framework."""
import argparse
from datetime import datetime, timezone
import ipaddress
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
from urllib.parse import urlsplit
import httpx
import yaml
from .findings import consolidate, gate, redact, render


def sanitized_log(value, token):
    if isinstance(value,bytes):
        value = value.decode('utf-8',errors='replace')
    return '\n'.join(redact(line.replace(token,'[REDACTED]')) for line in (value or '').splitlines())


def execute_zap(command, env, timeout, output, runtime, token):
    limitation = None
    try:
        result = subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',
                                env=env,timeout=timeout,shell=False,stdin=subprocess.DEVNULL)
        code,stdout,stderr = result.returncode,result.stdout,result.stderr
    except subprocess.TimeoutExpired as exc:
        code,stdout,stderr = 124,exc.stdout,exc.stderr
        limitation = f'ZAP process did not exit within {timeout} seconds'
    clean_log = sanitized_log(stdout,token)+'\n'+sanitized_log(stderr,token)
    (output/'zap.log').write_text(clean_log,encoding='utf-8')
    internal_log = runtime/'zap-home'/'zap.log'
    if internal_log.exists():
        (output/'zap-internal.log').write_text(sanitized_log(internal_log.read_bytes(),token),encoding='utf-8')
    if limitation:
        print(limitation,flush=True)
        print('\n'.join(clean_log.splitlines()[-40:]),flush=True)
    return code,clean_log,limitation


def preflight(config, resolve=socket.getaddrinfo):
    target = config['target'].rstrip('/')
    url = urlsplit(target)
    if url.scheme not in ('http','https') or not url.hostname or url.username or url.password or url.query or url.fragment or url.path:
        raise ValueError('Target must be an exact HTTP(S) origin without credentials, query or path')
    if target not in config['allowlist'] or not config.get('authorization','').strip():
        raise ValueError('Target requires exact allowlist and explicit authorization description')
    addresses = {row[4][0] for row in resolve(url.hostname,url.port or (443 if url.scheme=='https' else 80),type=socket.SOCK_STREAM)}
    internal = url.hostname in config.get('internal_hosts',[])
    if not addresses or not all(ipaddress.ip_address(ip).is_loopback or (internal and ipaddress.ip_address(ip).is_private) for ip in addresses):
        raise ValueError('Public or unlisted non-loopback target refused')
    return target


def seed(client):
    suffix = secrets.token_hex(5)
    users = []
    for name in ['scan_alice_','scan_bob_']:
        credentials = {'username':name+suffix,'password':secrets.token_urlsafe(24)}
        client.post('/auth/register',json=credentials).raise_for_status()
        login = client.post('/auth/login',json=credentials)
        login.raise_for_status()
        token = login.json()['access_token']
        headers = {'Authorization':'Bearer '+token}
        wallet = client.post('/wallets',headers=headers,json={'label':'DAST synthetic wallet'})
        wallet.raise_for_status()
        users.append({'token':token,'wallet':wallet.json()['id'],'headers':headers})
    alice,bob = users
    funded = client.post('/wallets/'+alice['wallet']+'/fund',headers={**alice['headers'],'Idempotency-Key':'scan-fund-'+suffix},json={'amount_minor':1000})
    funded.raise_for_status()
    moved = client.post('/transfers',headers={**alice['headers'],'Idempotency-Key':'scan-move-'+suffix},
                        json={'source_id':alice['wallet'],'destination_id':bob['wallet'],'amount_minor':100})
    moved.raise_for_status()
    checks = {}
    for name,path,method,body in [
        ('cross_wallet','/wallets/'+alice['wallet'],'GET',None),
        ('cross_history','/wallets/'+alice['wallet']+'/transactions','GET',None),
        ('cross_fund','/wallets/'+alice['wallet']+'/fund','POST',{'amount_minor':1}),
        ('cross_transaction','/transactions/'+funded.json()['id'],'GET',None),
        ('cross_transfer','/transfers','POST',{'source_id':alice['wallet'],'destination_id':bob['wallet'],'amount_minor':1})]:
        response = client.request(method,path,headers={**bob['headers'],'Idempotency-Key':'denied-'+name+'-'+suffix},json=body)
        checks[name] = response.status_code
        if response.status_code != 404:
            raise RuntimeError('Authenticated cross-account security check failed: '+name)
    return alice['token'],alice['wallet'],checks


def prepare_spec(spec, target, profile):
    # Never fetch arbitrary references/servers supplied by an untrusted target specification.
    def inspect(value):
        if isinstance(value,dict):
            if '$ref' in value and not value['$ref'].startswith('#/'):
                raise ValueError('External OpenAPI references are forbidden')
            if 'servers' in value:
                value['servers'] = [{'url':target}]
            for child in value.values():
                inspect(child)
        elif isinstance(value,list):
            for child in value:
                inspect(child)
    inspect(spec)
    spec['servers'] = [{'url':target}]
    paths = {}
    for path,methods in spec['paths'].items():
        if not path.startswith('/') or path.startswith('//') or '?' in path or '#' in path or '..' in path:
            raise ValueError('Unsafe OpenAPI path')
        if path.startswith('/auth/') and path != '/auth/me' or path.endswith('/fund'):
            continue
        selected = {k:v for k,v in methods.items() if k=='get' or profile=='active' and k in ('post','put','patch','delete')}
        if selected:
            paths[path] = selected
    spec['paths'] = paths
    return spec


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config',default='security/target.local.json')
    parser.add_argument('--profile',choices=['passive','active'],default='passive')
    parser.add_argument('--output',default='reports/current')
    parser.add_argument('--seed-wallet',action='store_true',help='Create synthetic users on the reference wallet')
    parser.add_argument('--compose',action='store_true')
    parser.add_argument('--zap-jar',help='Portable ZAP jar path; otherwise use local zap.sh')
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--timeout-seconds',type=int,help='Process deadline; defaults to 600 passive / 1200 active seconds')
    args = parser.parse_args()
    timeout = args.timeout_seconds if args.timeout_seconds is not None else (600 if args.profile=='passive' else 1200)
    if not 1 <= timeout <= 3600:
        parser.error('--timeout-seconds must be between 1 and 3600')
    output = Path(args.output).resolve()
    output.mkdir(parents=True,exist_ok=True)
    path = output/'manifest.json'
    started_at = datetime.now(timezone.utc).isoformat()
    manifest = json.loads(path.read_text()) if path.exists() else {'runs':[]}
    manifest['runs'] = [r for r in manifest['runs'] if r['tool']!='zap']
    manifest['runs'].append({'tool':'zap','scope':'unverified-target:'+args.profile,'status':'failed',
                             'exit_code':None,'file':str(output/'zap.json'),'started_at':started_at,
                             'limitation':'DAST preflight, preparation or execution did not complete'})
    path.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    config = json.loads(Path(args.config).read_text())
    if args.compose:
        # Resolve the scanner origin from its own isolated Docker network, before any HTTP requests.
        source = 'import ipaddress,socket,json,sys\nfrom urllib.parse import urlsplit\n'+inspect.getsource(preflight)+'\nprint(preflight(json.loads(sys.argv[1])))\n'
        verified = subprocess.run(['docker','compose','--profile','security','run','--rm','--entrypoint','python3','zap',
                                   '-c',source,json.dumps(config)],capture_output=True,text=True,encoding='utf-8',
                                  errors='replace',timeout=120,check=True)
        target = verified.stdout.strip().splitlines()[-1]
        if target!=config['target'].rstrip('/'):
            raise ValueError('Container preflight did not confirm the configured origin')
    else:
        target = preflight(config)
    # Compose target is resolved by a scanner container; host seed/verification uses its exact loopback publish.
    client_target = config.get('client_target',target)
    if client_target != target:
        preflight({**config,'target':client_target,'allowlist':config['client_allowlist']})
    with httpx.Client(base_url=client_target,timeout=15,follow_redirects=False,trust_env=False) as client:
        if args.seed_wallet:
            token,wallet,checks = seed(client)
        else:
            token,wallet,checks = os.environ['WG_SCAN_TOKEN'],os.environ.get('WG_SCAN_WALLET',''),{}
        identity = client.get(config['identity_path'],headers={'Authorization':'Bearer '+token})
        if identity.status_code != 200:
            raise RuntimeError('DAST identity verification failed')
        response = client.get(config['openapi_path'])
        response.raise_for_status()
        spec = prepare_spec(response.json(),target,args.profile)
    runtime = Path('security/.runtime').resolve()
    runtime.mkdir(parents=True,exist_ok=True)
    (output/'authorization-checks.json').write_text(json.dumps({'target':target,'identity_status':200,'checks':checks},indent=2))
    spec_path = runtime/'openapi.json'
    spec_path.write_text(json.dumps(spec),encoding='utf-8')
    vars = {'target':target,'targetRegex':re.escape(target),'walletId':wallet,
            'openapiFile':'/zap/wrk/openapi.json' if args.compose else str(spec_path),
            'reportDir':'/zap/wrk' if args.compose else str(output)}
    template = Path(f'security/zap/{args.profile}.yaml').read_text()
    plan = yaml.safe_load(template)
    def substitute(value):
        if isinstance(value,str):
            for key,replacement in vars.items():
                value = value.replace('${'+key+'}',replacement)
            return value
        if isinstance(value,list):
            return [substitute(v) for v in value]
        if isinstance(value,dict):
            return {k:substitute(v) for k,v in value.items()}
        return value
    plan_path = runtime/'zap-plan.yaml'
    plan_path.write_text(yaml.safe_dump(substitute(plan),sort_keys=False),encoding='utf-8')
    if args.prepare_only:
        print('Preflight, normal-user identity and plan preparation completed; ZAP has not run.')
        return
    env = {**os.environ,'ZAP_AUTH_HEADER':'Authorization','ZAP_AUTH_HEADER_VALUE':'Bearer '+token,
           'ZAP_AUTH_HEADER_SITE':urlsplit(target).hostname}
    if args.compose:
        command = ['docker','compose','--profile','security','run','--rm','zap']
    elif args.zap_jar:
        command = ['java','-Djava.awt.headless=true','-jar',str(Path(args.zap_jar).resolve()),'-cmd','-autorun',
                   str(plan_path),'-silent','-dir',str(runtime/'zap-home'),'-config','api.disablekey=false']
    else:
        command = ['zap.sh','-cmd','-autorun',str(plan_path),'-silent','-dir',str(runtime/'zap-home')]
    report_file = output/'zap.json'
    if report_file.exists():
        report_file.unlink()
    if args.compose and (runtime/'zap.json').exists():
        (runtime/'zap.json').unlink()
    code,clean_log,limitation = execute_zap(command,env,timeout,output,runtime,token)
    if args.compose and (runtime/'zap.json').exists():
        report_file.write_bytes((runtime/'zap.json').read_bytes())
    status = 'success' if code in (0,1,2) and report_file.exists() and 'Automation plan failures:' not in clean_log else 'failed'
    path = output/'manifest.json'
    manifest = json.loads(path.read_text()) if path.exists() else {'runs':[]}
    manifest['runs'] = [r for r in manifest['runs'] if r['tool']!='zap']
    record = {'tool':'zap','scope':target+':'+args.profile,'status':status,'exit_code':code,
              'file':str(report_file),'started_at':started_at}
    if limitation:
        record['limitation'] = limitation
    manifest['runs'].append(record)
    path.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    report = consolidate(manifest,exceptions=json.loads(Path('security/exceptions.json').read_text()),
                         triage=json.loads(Path('security/triage.json').read_text()))
    render(report,output)
    print(json.dumps({'zap_status':status,'exit_code':code,'findings':len(report['findings']),
                      'authorization_checks':checks,'gate_failed':gate(report)}))
    if gate(report):
        raise SystemExit(1)


if __name__=='__main__':
    main()
