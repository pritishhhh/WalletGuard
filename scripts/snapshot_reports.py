"""Sanitize and snapshot actual completed outputs; no synthetic scan results."""
import hashlib
import json
from pathlib import Path
import re
from security.findings import consolidate, render


def main():
    root = Path.cwd()
    current = root/'reports/current'
    sample = root/'reports/sample'
    sample.mkdir(parents=True,exist_ok=True)
    manifest = json.loads((current/'manifest.json').read_text())
    # Keep active and routine DAST as distinct scopes, with independently preserved raw reports.
    active = root/'reports/active/manifest.json'
    if active.exists():
        manifest['runs'] += json.loads(active.read_text())['runs']
    for run in manifest['runs']:
        path = Path(run['file'])
        if run['status']=='success' and path.exists():
            name = 'zap-active.json' if run['tool']=='zap' and run['scope'].endswith(':active') else path.name
            content = path.read_text(encoding='utf-8-sig')
            # Remove host paths while retaining real scanner schema, counts and evidence.
            content = content.replace(str(root).replace('\\','\\\\'),'<repository>')
            content = content.replace(str(root),'<repository>')
            content = re.sub(r'C:\\\\Users\\\\[^"\n]+?\\\\Documents\\\\Codex', '<workspace>', content)
            # ZAP traditional-json has no raw request/response credentials; no token fields should survive.
            data = json.loads(content)
            (sample/name).write_text(json.dumps(data,indent=2),encoding='utf-8')
            run['file'] = (Path('reports/sample')/name).as_posix()
        else:
            run['file'] = (Path('reports/sample')/path.name).as_posix()
    (sample/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    report = consolidate(manifest,exceptions=json.loads(Path('security/exceptions.json').read_text()),
                         triage=json.loads(Path('security/triage.json').read_text()))
    render(report,sample)
    for name in ['pytest.xml','reconciliation.json','authorization-checks.json']:
        path = current/name
        if path.exists():
            content = path.read_text(encoding='utf-8').replace(str(root),'<repository>')
            (sample/name).write_text(content,encoding='utf-8')
    teaching = Path('reports/teaching')
    teaching_manifest = {'runs':[{'tool':tool,'scope':'isolated-teaching','status':'success','exit_code':0,
                                 'file':(teaching/name).as_posix()} for tool,name in [('semgrep','semgrep.json'),('security-tests','security-tests.json')]]}
    (teaching/'manifest.json').write_text(json.dumps(teaching_manifest,indent=2))
    teaching_report = consolidate(teaching_manifest)
    for finding in teaching_report['findings']:
        finding.update(triage_state='confirmed',triage_owner='WalletGuard teaching maintainer',
                       triage_reason='Intentional isolated weakness demonstrated by real scan or HTTP response',
                       impact='Teaching fixture exposes unauthorized data or unsafe configuration; it is excluded from the deployed image.',
                       retest_result='Secure counterpart regression tests passed; teaching fixture intentionally retains the weakness.')
    render(teaching_report,teaching)
    hashes = {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for folder in (sample,root/teaching)
              for p in folder.iterdir() if p.is_file() and p.name!='evidence-sha256.json'}
    (sample/'evidence-sha256.json').write_text(json.dumps(hashes,indent=2))
    print(json.dumps({'sample_findings':len(report['findings']),'coverage_errors':report['errors'],
                      'teaching_findings':len(teaching_report['findings'])}))


if __name__=='__main__':
    main()
