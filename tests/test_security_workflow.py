from datetime import date, timedelta
import json
import pytest
from security.dast import preflight, prepare_spec
from security.findings import consolidate, gate, parse, redact, render


def resolve(ip):
    return lambda *args,**kwargs: [(2,1,6,'',(ip,8000))]


@pytest.mark.parametrize('target,allowlist,ip', [
    ('http://public.example',['http://public.example'],'8.8.8.8'),
    ('http://127.0.0.1:8000',[],'127.0.0.1'),
    ('http://user:pass@127.0.0.1:8000',['http://user:pass@127.0.0.1:8000'],'127.0.0.1'),
    ('http://127.0.0.1:8000/path',['http://127.0.0.1:8000/path'],'127.0.0.1')])
def test_dast_rejects_unauthorized_target(target,allowlist,ip):
    with pytest.raises(ValueError):
        preflight({'target':target,'allowlist':allowlist,'authorization':'test'},resolve(ip))


def test_dast_accepts_loopback_and_explicit_internal():
    config = {'target':'http://127.0.0.1:8000','allowlist':['http://127.0.0.1:8000'],'authorization':'owned local'}
    assert preflight(config,resolve('127.0.0.1')) == config['target']
    config = {'target':'http://wallet-api:8000','allowlist':['http://wallet-api:8000'],'authorization':'owned local',
              'internal_hosts':['wallet-api']}
    assert preflight(config,resolve('172.18.0.2')) == config['target']


def test_openapi_no_external_refs_and_passive_read_only():
    with pytest.raises(ValueError):
        prepare_spec({'paths':{},'components':{'bad':{'$ref':'https://third-party.example/spec'}}},'http://127.0.0.1:8000','passive')
    spec = prepare_spec({'paths':{'/wallets':{'get':{},'post':{}},'/auth/login':{'post':{}}}},'http://127.0.0.1:8000','passive')
    assert spec['paths'] == {'/wallets':{'get':{}}}


def test_report_dedup_baseline_fixed_and_missing_coverage(tmp_path):
    report = tmp_path/'scan.json'
    row = {'rule':'r1','component':'component','severity':'high','evidence':'observed','fix':'repair'}
    report.write_text(json.dumps({'findings':[row,row]}))
    manifest = {'runs':[{'tool':'security-tests','scope':'fixture','status':'success','file':str(report)}]}
    first = consolidate(manifest)
    assert len(first['findings']) == 1 and first['findings'][0]['status']=='new'
    repeated = consolidate(manifest,first)
    assert repeated['findings'][0]['status']=='existing'
    assert repeated['findings'][0]['first_seen']==first['findings'][0]['first_seen']
    report.write_text(json.dumps({'findings':[]}))
    fixed = consolidate(manifest,first)
    assert fixed['findings'][0]['status']=='fixed' and not gate(fixed)
    missing = consolidate({'runs':[]},first)
    assert missing['findings'][0]['status']=='unverified' and gate(missing)


def test_suppression_requires_reason_owner_expiry_and_reports_escape(tmp_path):
    path = tmp_path/'scan.json'
    path.write_text(json.dumps({'findings':[{'rule':'<script>alert(1)</script>','component':'x','severity':'high',
                                            'evidence':'Bearer sensitive123','fix':'fix'}]}))
    manifest = {'runs':[{'tool':'security-tests','scope':'test','status':'success','file':str(path)}]}
    report = consolidate(manifest)
    fid = report['findings'][0]['id']
    exception = {'id':fid,'reason':'isolated fixture','owner':'security','expires':str(date.today()+timedelta(days=1))}
    suppressed = consolidate(manifest,exceptions=[exception])
    assert suppressed['findings'][0]['status']=='suppressed' and not gate(suppressed)
    with pytest.raises(ValueError):
        consolidate(manifest,exceptions=[{'id':fid}])
    with pytest.raises(ValueError):
        consolidate(manifest,exceptions=[{**exception,'expires':'2000-01-01'}])
    render(report,tmp_path/'out')
    assert '<script>' not in (tmp_path/'out'/'findings.html').read_text()
    assert 'sensitive123' not in (tmp_path/'out'/'findings.json').read_text()


@pytest.mark.parametrize('tool,data', [('semgrep',{'results':[],'errors':[{'message':'failed'}]}),('zap',{}),
                                      ('trivy-config',{}),('pip-audit',{}),('gitleaks',{})])
def test_malformed_scanner_output_never_clean(tool,data):
    with pytest.raises(ValueError):
        parse(tool,'scope',data)


def test_secret_redaction():
    assert 'secret123' not in redact('postgresql://u:secret123@db/wallet')
    assert 'token123' not in redact('Bearer token123')


def test_dast_preflight_failure_is_recorded_as_missing_coverage(tmp_path,monkeypatch):
    from security.dast import main
    config = tmp_path/'target.json'
    config.write_text(json.dumps({'target':'http://user:pass@127.0.0.1:8000','allowlist':[],
                                  'authorization':'test'}))
    output = tmp_path/'reports'
    monkeypatch.setattr('sys.argv',['dast','--config',str(config),'--output',str(output)])
    with pytest.raises(ValueError):
        main()
    manifest = json.loads((output/'manifest.json').read_text())
    report = consolidate(manifest)
    assert manifest['runs'][0]['status']=='failed' and report['errors'] and gate(report)
    assert 'user:pass' not in (output/'manifest.json').read_text()


def test_zap_timeout_preserves_redacted_partial_and_internal_logs(tmp_path,monkeypatch):
    import subprocess
    from security.dast import execute_zap
    token = 'SyntheticSecretForTimeoutTest'
    runtime = tmp_path/'runtime'
    home = runtime/'zap-home'
    home.mkdir(parents=True)
    (home/'zap.log').write_text('Startup error\nAuthorization: Bearer '+token)
    def timeout(*args,**kwargs):
        raise subprocess.TimeoutExpired(args[0],5,output=('Job openapi started\nBearer '+token).encode(),
                                        stderr=b'blocked operation')
    monkeypatch.setattr('security.dast.subprocess.run',timeout)
    code,log,reason = execute_zap(['zap.sh'],{},5,tmp_path,runtime,token)
    assert code==124 and reason and 'Job openapi started' in log and 'blocked operation' in log
    assert token not in log and token not in (tmp_path/'zap-internal.log').read_text()


def test_zap_completed_scan_logs_redact_credentials(tmp_path,monkeypatch):
    import subprocess
    from security.dast import execute_zap
    def completed(*args,**kwargs):
        return subprocess.CompletedProcess(args[0],0,'Automation plan succeeded!\nBearer fake-secret',
                                           'https://user:password123@target/path')
    monkeypatch.setattr('security.dast.subprocess.run',completed)
    code,log,reason = execute_zap(['zap.sh'],{},10,tmp_path,tmp_path/'runtime','fake-secret')
    assert code==0 and reason is None and 'Automation plan succeeded!' in log
    assert 'fake-secret' not in log and 'password123' not in log
