"""Run separate scanners and preserve successful/failed coverage explicitly."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from .findings import consolidate, gate, render


def run_scanner(manifest, tool, scope, args, output, allowed_codes=(0,1)):
    started = time.monotonic()
    record = {'tool':tool,'scope':scope,'file':str(output),'started_at':datetime.now(timezone.utc).isoformat()}
    if output.exists():
        output.unlink()
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=900, shell=False,
                                env={**os.environ,'SEMGREP_SEND_METRICS':'off'})
        (output.parent/(tool+'.log')).write_text(result.stdout+'\n'+result.stderr,encoding='utf-8')
        record.update(exit_code=result.returncode,status='success' if result.returncode in allowed_codes and output.exists() else 'failed')
    except (OSError,subprocess.TimeoutExpired) as exc:
        record.update(exit_code=None,status='unavailable',limitation=type(exc).__name__)
    record['duration_seconds'] = round(time.monotonic()-started,3)
    manifest['runs'].append(record)
    print(f"{tool}: {record['status']} (exit {record['exit_code']})",flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('profile',choices=['static','container'])
    parser.add_argument('--output',default='reports/current')
    parser.add_argument('--semgrep',default=shutil.which('semgrep') or 'semgrep')
    parser.add_argument('--pip-audit',default=shutil.which('pip-audit') or 'pip-audit')
    parser.add_argument('--trivy',default=shutil.which('trivy') or 'trivy')
    parser.add_argument('--gitleaks',default=shutil.which('gitleaks') or 'gitleaks')
    parser.add_argument('--image',default='walletguard:local')
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True,exist_ok=True)
    path = output/'manifest.json'
    manifest = json.loads(path.read_text()) if path.exists() else {'runs':[]}
    selected = {'semgrep','pip-audit','trivy-config','gitleaks'} if args.profile=='static' else {'trivy-image'}
    manifest['runs'] = [r for r in manifest['runs'] if r['tool'] not in selected]
    if args.profile == 'static':
        run_scanner(manifest,'semgrep','secure-source',[args.semgrep,'scan','--config','security/semgrep.yml','--metrics','off',
                    '--disable-version-check','--json','--output',str(output/'semgrep.json'),'walletguard','security','migrations','scripts'],output/'semgrep.json', (0,))
        run_scanner(manifest,'pip-audit','runtime-dependencies',[args.pip_audit,'-r','requirements.txt','--disable-pip','--no-deps',
                    '--format','json','--output',str(output/'pip-audit.json')],output/'pip-audit.json')
        run_scanner(manifest,'trivy-config','deployment',[args.trivy,'config','--format','json','--output',str(output/'trivy-config.json'),
                    '--skip-dirs','teaching,reports,.venv','.'],output/'trivy-config.json',(0,))
        run_scanner(manifest,'gitleaks','repository',[args.gitleaks,'dir','.','--config','security/gitleaks.toml','--redact',
                    '--report-format','json','--report-path',str(output/'gitleaks.json')],output/'gitleaks.json')
    else:
        run_scanner(manifest,'trivy-image','container:'+args.image,[args.trivy,'image','--scanners','vuln','--format','json','--output',
                    str(output/'trivy-image.json'),args.image],output/'trivy-image.json',(0,))
    path.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    report = consolidate(manifest,exceptions=json.loads(Path('security/exceptions.json').read_text()),
                         triage=json.loads(Path('security/triage.json').read_text()))
    render(report,output)
    if gate(report):
        raise SystemExit(1)


if __name__=='__main__':
    main()
