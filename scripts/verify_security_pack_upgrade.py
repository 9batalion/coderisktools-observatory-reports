#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys

ALLOWED={
 '.github/workflows/validate-publication.yml','README.md','pyproject.toml','run_state.json','governance/repository-policy.json',
 'docs/NAMED_WEEKLY_OSS_REVIEW_V1.md','docs/SECURITY_PACK_UPGRADE_V020.md','docs/POPULARITY_RANKING_V1.md',
 'schemas/named-weekly-index.v1.schema.json','schemas/named-weekly-review.v1.schema.json','schemas/private-weekly-trial.v1.schema.json','schemas/popularity-ranking.v1.schema.json',
 'scripts/build_named_weekly.py','scripts/verify_release_repo.py','scripts/verify_security_pack_upgrade.py','scripts/verify_weekly_immutability.py','scripts/verify_weekly_pr_metadata.py',
 'tests/test_named_weekly_builder.py','tests/test_named_weekly_reviews.py','tests/test_popularity_ranking.py',
}
REQUIRED_NEW={
 'docs/POPULARITY_RANKING_V1.md','schemas/popularity-ranking.v1.schema.json','tests/test_popularity_ranking.py',
}
IGNORE={'.git','__pycache__','.pytest_cache'}
def fail(message):raise ValueError(message)
def digest(data):return hashlib.sha256(data).hexdigest()
def inventory(root):
    result={};portable=set()
    for path in root.rglob('*'):
        relative=path.relative_to(root);parts=relative.parts
        if any(part in IGNORE for part in parts) or path.suffix=='.pyc':continue
        name=PurePosixPath(*parts).as_posix()
        if path.is_symlink():fail(f'symlink rejected: {name}')
        if path.is_dir():continue
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>20_000_000:fail(f'unsafe file: {name}')
        key=name.casefold()
        if key in portable:fail(f'portable path collision: {name}')
        portable.add(key);raw=path.read_bytes();after=path.lstat()
        if len(raw)!=info.st_size or (info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns):fail(f'file changed during read: {name}')
        result[name]=raw
    return result
def run(command,cwd):
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';result=subprocess.run(command,cwd=cwd,env=env,capture_output=True,text=True)
    if result.returncode:fail(f'gate failed: {" ".join(command)}\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}')
    return result.stdout.strip()
def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--base',required=True,type=Path);parser.add_argument('--candidate',required=True,type=Path);parser.add_argument('--run-tests',action='store_true');args=parser.parse_args(argv)
    try:
        base=args.base.resolve(strict=True);candidate=args.candidate.resolve(strict=True);base_files=inventory(base);candidate_files=inventory(candidate)
        for prefix in ('public/','operator/'):
            before={k:v for k,v in base_files.items() if k.startswith(prefix)};after={k:v for k,v in candidate_files.items() if k.startswith(prefix)}
            if before!=after:fail(f'security-pack bootstrap changed protected payload root: {prefix}')
        changed={name for name in set(base_files)|set(candidate_files) if base_files.get(name)!=candidate_files.get(name)}
        deleted=set(base_files)-set(candidate_files)
        if deleted:fail(f'security-pack bootstrap deleted files: {sorted(deleted)}')
        if not REQUIRED_NEW<=changed or not changed<=ALLOWED:fail(f'non-exact security-pack change set: {sorted(changed)}')
        state=json.loads(candidate_files['run_state.json']);
        if state.get('version')!='0.3.0' or state.get('remote_promoted') is not False:fail('candidate state is not unpromoted v0.3.0')
        workflow=candidate_files['.github/workflows/validate-publication.yml'].decode()
        for token in ('trusted/scripts/verify_weekly_pr_metadata.py','trusted/scripts/verify_weekly_immutability.py','trusted/scripts/verify_release_repo.py','github.event.pull_request.head.sha'):
            if token not in workflow:fail(f'candidate workflow lacks trusted token: {token}')
        verification=run([sys.executable,'scripts/verify_release_repo.py','--root','.'],candidate)
        if args.run_tests:
            run([sys.executable,'-m','unittest','discover','-s','tests','-q'],candidate);run([sys.executable,'-O','-m','unittest','discover','-s','tests','-q'],candidate)
        print(json.dumps({'status':'SECURITY_PACK_UPGRADE_OK','version':'0.3.0','changed_paths':sorted(changed),'changed_count':len(changed),'candidate_inventory_sha256':digest(b''.join(name.encode()+b'\0'+digest(candidate_files[name]).encode()+b'\n' for name in sorted(candidate_files))),'release_verification':verification},sort_keys=True,separators=(',',':')));return 0
    except (OSError,UnicodeDecodeError,ValueError,json.JSONDecodeError) as exc:
        print(f'SECURITY_PACK_UPGRADE_FAILED: {exc}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
