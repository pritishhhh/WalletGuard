"""Download pinned official scanner archives and verify published checksums."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
import urllib.request
import zipfile

VERSIONS = {'trivy':'0.75.0','gitleaks':'8.30.1'}
PROJECTS = {'trivy':'aquasecurity/trivy','gitleaks':'gitleaks/gitleaks'}


def download(url):
    with urllib.request.urlopen(url,timeout=60) as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',default='security/.runtime/bin')
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True,exist_ok=True)
    system = platform.system()
    windows = system=='Windows'
    if system not in ('Windows','Linux','Darwin'):
        raise SystemExit('Install the pinned scanner releases manually for this operating system')
    if platform.machine().lower() not in ('amd64','x86_64'):
        raise SystemExit('This helper supports x64; install pinned releases for your architecture manually')
    for name,version in VERSIONS.items():
        release = json.loads(download('https://api.github.com/repos/'+PROJECTS[name]+'/releases/tags/v'+version))
        suffix = ({'Windows':'Windows-64bit.zip','Linux':'Linux-64bit.tar.gz','Darwin':'macOS-64bit.tar.gz'}[system]
                  if name=='trivy' else {'Windows':'windows_x64.zip','Linux':'linux_x64.tar.gz','Darwin':'darwin_x64.tar.gz'}[system])
        archive = next(a for a in release['assets'] if a['name'].endswith(suffix))
        checksums = next(a for a in release['assets'] if a['name'].endswith('checksums.txt'))
        checksum_data = download(checksums['browser_download_url']).decode()
        expected = next(line.split()[0] for line in checksum_data.splitlines() if line.split()[-1].lstrip('*')==archive['name'])
        data = download(archive['browser_download_url'])
        if hashlib.sha256(data).hexdigest()!=expected:
            raise ValueError('Scanner checksum mismatch')
        # Extract only the scanner binary, not arbitrary archive paths.
        binary = name+('.exe' if windows else '')
        if windows:
            source = zipfile.ZipFile(io.BytesIO(data)).read(binary)
        else:
            archive_reader = tarfile.open(fileobj=io.BytesIO(data),mode='r:gz')
            source = archive_reader.extractfile(binary).read()
        path = output/binary
        path.write_bytes(source)
        if not windows:
            path.chmod(0o755)
        print(f'{name} {version} verified and installed at {path}')


if __name__=='__main__':
    main()
