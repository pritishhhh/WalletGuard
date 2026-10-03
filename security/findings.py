"""Strict scanner parsers; scoped baselines; expiring, accountable exceptions."""
import argparse
from datetime import date, datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

TOOLS = {'semgrep','pip-audit','trivy-config','trivy-image','gitleaks','zap','security-tests'}
SEVERITIES = {'INFO':'info','LOW':'low','WARNING':'medium','MEDIUM':'medium','ERROR':'high','HIGH':'high',
              'CRITICAL':'critical','UNKNOWN':'unknown','0':'info','1':'low','2':'medium','3':'high'}


def redact(value):
    value = re.sub(r'(?i)(bearer\s+)[a-z0-9._~-]+', r'\1[REDACTED]', str(value))
    value = re.sub(r'(?i)((?:password|access_token|token|secret)\s*[=:]\s*)[^\s,;<>]+',r'\1[REDACTED]',value)
    value = re.sub(r'://[^/@\s]+:[^/@\s]+@','://[REDACTED]@',value)
    return value[:3000]


def component(value):
    value = str(value).replace('\\','/')
    if value.startswith(('http://','https://')):
        parsed = urlsplit(value)
        value = parsed.scheme+'://'+parsed.netloc+parsed.path
        value = re.sub(r'[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}', '{uuid}',value)
    return redact(value)


def finding(tool, scope, rule, affected, severity, evidence, fix, cwe=None, owasp=None):
    affected = component(affected)
    key = json.dumps([tool,scope,str(rule),affected],separators=(',',':'))
    return {'id':hashlib.sha256(key.encode()).hexdigest()[:20], 'tool':tool,'scope':scope,'rule':str(rule),
            'component':affected,'severity':SEVERITIES.get(str(severity).upper(),'unknown'),
            'evidence':redact(evidence),'recommended_fix':redact(fix), 'cwe':cwe or [],'owasp':owasp or [],
            'reproduction':f'Rerun {tool} for scope {scope}; inspect rule {rule} at {affected}.',
            'impact':'Assess exploitability and exposure from the preserved evidence.',
            'retest_result':'Pending developer retest', 'triage_state':'unreviewed'}


def parse(tool, scope, data):
    result = []
    def add(*args,**kwargs):
        result.append(finding(tool,scope,*args,**kwargs))
    if tool == 'semgrep':
        if 'results' not in data or data.get('errors'):
            raise ValueError('Semgrep report missing results or contains scanner errors')
        for row in data['results']:
            extra = row['extra']
            meta = extra.get('metadata',{})
            add(row['check_id'],row['path'],extra['severity'],
                f"line {row['start']['line']}: {extra['message']}",extra['message'],
                meta.get('cwe',[]),meta.get('owasp',[]))
    elif tool == 'pip-audit':
        if 'dependencies' not in data:
            raise ValueError('Invalid pip-audit report')
        for dependency in data['dependencies']:
            for vuln in dependency['vulns']:
                add(vuln['id'],dependency['name'], 'UNKNOWN',
                    f"Installed {dependency['version']}. {vuln.get('description','')} Aliases: {vuln.get('aliases',[])}",
                    f"Upgrade to a non-vulnerable version. Available fixes: {vuln.get('fix_versions',[])}")
    elif tool.startswith('trivy'):
        if 'SchemaVersion' not in data:
            raise ValueError('Invalid Trivy report')
        for target in data.get('Results',[]) or []:
            for vuln in target.get('Vulnerabilities',[]) or []:
                add(vuln['VulnerabilityID'],target['Target']+':'+vuln['PkgName'],vuln['Severity'],
                    f"Installed {vuln['InstalledVersion']}: {vuln.get('Title','')}",
                    f"Upgrade to {vuln.get('FixedVersion','a non-vulnerable supported version')}",vuln.get('CweIDs',[]))
            for mis in target.get('Misconfigurations',[]) or []:
                add(mis['ID'],target['Target'],mis['Severity'],mis.get('Message',mis.get('Title','')),
                    mis.get('Resolution','Review the configuration reference'),owasp=['A02:2025'])
    elif tool == 'gitleaks':
        if not isinstance(data,list):
            raise ValueError('Invalid Gitleaks report')
        for row in data:
            add(row['RuleID'],row['File'],'HIGH',f"Potential secret at line {row['StartLine']}; value intentionally removed",
                'Revoke/rotate any real credential, remove it from source and history, and use secret injection.',
                ['CWE-798'],['A04:2025'])
    elif tool == 'zap':
        if 'site' not in data:
            raise ValueError('Invalid ZAP report')
        for site in data['site']:
            for alert in site.get('alerts',[]):
                for instance in alert.get('instances',[]) or [{'uri':site['@name']}]:
                    fix = alert.get('solution','') or ('Compare the same authenticated request with different User-Agent headers; '
                            'review unexpected status codes or response data. This informational alert alone does not prove a vulnerability.'
                            if str(alert['pluginid'])=='10104' else 'Review the alert evidence and upstream rule guidance, implement the relevant control and rerun ZAP.')
                    add(alert['pluginid'],instance['uri'],alert['riskcode'],
                        alert.get('name',alert.get('alert',''))+' '+instance.get('evidence','')+' '+
                        instance.get('otherinfo',alert.get('otherinfo',''))+' '+
                        f"Method: {instance.get('method','')}; parameter: {instance.get('param','')}; payload: {instance.get('attack','')}",fix,
                        ['CWE-'+str(alert['cweid'])] if str(alert.get('cweid','0'))!='0' else [],
                        list((alert.get('tags') or {}).keys()))
    elif tool == 'security-tests':
        if 'findings' not in data:
            raise ValueError('Invalid behavioral evidence report')
        for row in data['findings']:
            add(row['rule'],row['component'],row['severity'],row['evidence'],row['fix'],row.get('cwe'),row.get('owasp'))
    else:
        raise ValueError('Unknown scanner')
    return result


def consolidate(manifest, baseline=None, exceptions=None, triage=None):
    now = datetime.now(timezone.utc).isoformat()
    baseline = baseline or {'findings':[]}
    triage = triage or {}
    previous = {f['id']:f for f in baseline['findings'] if f['status'] != 'fixed'}
    current, coverage, errors = {},set(),[]
    if not manifest['runs']:
        errors.append('No scanner runs were supplied')
    for run in manifest['runs']:
        if run['tool'] not in TOOLS or run['status'] != 'success':
            errors.append(f"{run['tool']} ({run['scope']}): {run['status']}")
            continue
        try:
            data = json.loads(Path(run['file']).read_text(encoding='utf-8-sig'))
            rows = parse(run['tool'],run['scope'],data)
        except (ValueError,KeyError,TypeError,OSError) as exc:
            errors.append(f"{run['tool']}: invalid or missing report ({type(exc).__name__})")
            continue
        coverage.add((run['tool'],run['scope']))
        for row in rows:
            if row['id'] in current:
                continue
            old = previous.get(row['id'])
            row.update(status='existing' if old else 'new', first_seen=old['first_seen'] if old else now,last_seen=now)
            current[row['id']] = row
    for old in previous.values():
        if old['id'] not in current:
            row = dict(old)
            if (row['tool'],row['scope']) in coverage:
                row.update(status='fixed',retest_result='Absent in successful current scan of the same scope')
            else:
                row.update(status='unverified',retest_result='Tool/scope not successfully rerun; fix not verified')
            current[row['id']] = row
    for row in current.values():
        item = triage.get(row['id'])
        if item:
            if item.get('state') not in ('confirmed','false-positive','accepted-risk','investigating') or not item.get('owner') or not item.get('reason'):
                raise ValueError('Triage requires valid state, owner and reason')
            row.update(triage_state=item['state'],triage_owner=item['owner'],triage_reason=item['reason'])
            for key in ('reproduction','impact','recommended_fix','retest_result'):
                if key in item:
                    row[key] = redact(item[key])
    for exception in exceptions or []:
        if not all(exception.get(k) for k in ('id','reason','owner','expires')):
            raise ValueError('Suppression requires id, reason, owner and expiry')
        expiry = date.fromisoformat(exception['expires'])
        if expiry < date.today():
            raise ValueError('Expired suppression must be reviewed and removed')
        row = current.get(exception['id'])
        if row and row['status'] in ('new','existing','unverified'):
            row.update(status='suppressed',suppression=exception)
    return {'generated_at':now,'coverage':sorted([list(x) for x in coverage]),'errors':errors,
            'runs':manifest['runs'],'findings':sorted(current.values(),key=lambda x:(x['severity'],x['component'],x['id']))}


def render(report, output):
    output = Path(output)
    output.mkdir(parents=True,exist_ok=True)
    (output/'findings.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    lines = ['# WalletGuard generated security report', '', 'Generated: '+report['generated_at'], '',
             'This report contains actual scanner evidence. Zero findings only describes the successful listed coverage.', '',
             '## Coverage', '']
    for run in report['runs']:
        lines.append(f"- {run['tool']} / {run['scope']}: {run['status']} (exit {run.get('exit_code','n/a')})")
    for error in report['errors']:
        lines.append('- INCOMPLETE: '+error)
    lines += ['', '## Developer findings', '']
    if not report['findings']:
        lines.append('No findings in successful scan outputs. Authorization and business logic still require behavioral tests.')
    for row in report['findings']:
        lines += [f"### {row['id']} — {row['rule']}", '',
                  f"{row['severity']} | {row['status']} | {row['triage_state']} | {row['tool']} | {row['component']}", '',
                  'Evidence: '+row['evidence'], '', 'Reproduction: '+row['reproduction'], '',
                  'Impact: '+row['impact'], '', 'Fix: '+row['recommended_fix'], '',
                  'Retest: '+row['retest_result'], '',
                  f"First seen: {row['first_seen']}; last seen: {row['last_seen']}", '',
                  f"CWE: {row['cwe']}; OWASP: {row['owasp']}", '']
    markdown = '\n'.join(lines)
    (output/'findings.md').write_text(markdown,encoding='utf-8')
    cards = ''.join('<article><h2>'+html.escape(row['rule'])+'</h2><p class="meta">'+html.escape(
                   row['severity']+' · '+row['status']+' · '+row['tool'])+'</p><code>'+html.escape(row['component'])+
                   '</code>'+''.join('<h3>'+label+'</h3><p>'+html.escape(row[key])+'</p>' for label,key in
                   [('Evidence','evidence'),('Reproduction','reproduction'),('Impact','impact'),('Fix','recommended_fix'),('Retest','retest_result')])+
                   '</article>' for row in report['findings'])
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>WalletGuard Security Report</title><style>body{background:#0c1423;color:#e6edf8;font:16px system-ui;margin:0}
main{max-width:1050px;margin:auto;padding:48px 24px}header{border-bottom:1px solid #2c3e58;padding-bottom:24px}
h1{font-size:42px;letter-spacing:-1px;margin:12px 0}h2{font-size:22px}.brand{color:#64dcc0;letter-spacing:3px}
article{padding:28px;background:#142135;border:1px solid #2c3e58;border-radius:12px;margin:24px 0}
code{overflow-wrap:anywhere;color:#94dbe9}.meta{color:#a6bad4}p{line-height:1.6}h3{font-size:14px;color:#64dcc0}</style>
<main><header><div class="brand">WALLETGUARD / SECURITY</div><h1>Developer findings</h1><p class="meta">'''+html.escape(report['generated_at'])+'''</p></header><h2>Verified coverage</h2><ul>'''+''.join(
        '<li>'+html.escape(f"{r['tool']} · {r['scope']} · {r['status']}")+'</li>' for r in report['runs'])+'</ul>'+(
        '<p>'+html.escape('INCOMPLETE: '+'; '.join(report['errors']))+'</p>' if report['errors'] else '')+cards+(
        '<p>No findings in successful listed outputs.</p>' if not cards else '')+'</main></html>'
    (output/'findings.html').write_text(page,encoding='utf-8')


def gate(report):
    return bool(report['errors'] or any(f['severity'] in ('high','critical','unknown') and
                                     f['status'] not in ('fixed','suppressed') for f in report['findings']))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest',required=True)
    parser.add_argument('--baseline')
    parser.add_argument('--exceptions',default='security/exceptions.json')
    parser.add_argument('--triage',default='security/triage.json')
    parser.add_argument('--output',default='reports/current')
    parser.add_argument('--gate',action='store_true')
    args = parser.parse_args()
    def read(path,default):
        return json.loads(Path(path).read_text(encoding='utf-8')) if path else default
    report = consolidate(read(args.manifest,{}),read(args.baseline,None),read(args.exceptions,[]),read(args.triage,{}))
    render(report,args.output)
    print(json.dumps({'findings':len(report['findings']),'errors':report['errors'],'gate_failed':gate(report)}))
    if args.gate and gate(report):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
