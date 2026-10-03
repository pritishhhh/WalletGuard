"""Freeze the installed runtime dependency closure; run after a deliberate upgrade."""
from pathlib import Path
import importlib.metadata as metadata
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

todo = ['fastapi','uvicorn','sqlalchemy','alembic','psycopg','psycopg-binary','argon2-cffi','httpx','pyyaml']
seen = {}
while todo:
    name = todo.pop()
    if canonicalize_name(name) in seen:
        continue
    package = metadata.distribution(name)
    seen[canonicalize_name(name)] = (package.metadata['Name'],package.version)
    for line in package.requires or []:
        requirement = Requirement(line)
        if not requirement.marker or requirement.marker.evaluate():
            todo.append(requirement.name)
Path('requirements.txt').write_text(''.join(f'{name}=={version}\n' for name,version in sorted(seen.values())),encoding='utf-8')
Path('requirements-dev.txt').write_text('-r requirements.txt\npytest==9.1.1\nruff==0.16.10\niniconfig==2.3.0\npackaging==26.3\npluggy==1.6.0\nPygments==2.21.0\n',encoding='utf-8')
