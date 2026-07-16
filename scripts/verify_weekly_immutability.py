#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from verify_release_repo import canonical,regular_bytes,strict_json

MUTABLE={'public/weekly/index.json','public/weekly/latest.json','public/SHA256SUMS.txt','operator/pr-request.json'}
WEEK_FILES={'report.json','index.html'}

def fail(message):raise ValueError(message)
def iso_week(value):
    try:start=datetime.strptime(value+'-1','%G-W%V-%u').date()
    except (TypeError,ValueError) as exc:raise ValueError('invalid ISO week') from exc
    if start.strftime('%G-W%V')!=value:fail('non-canonical ISO week')
    return start

def lines(path:Path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>1_000_000:fail('invalid changed-path list')
    raw=path.read_bytes()
    if path.lstat().st_size!=len(raw):fail('changed-path list changed during read')
    values=raw.decode('utf-8').splitlines()
    if not values or len(values)>10_000 or len(values)!=len(set(values)):fail('empty, duplicate, or excessive changed-path list')
    return values

def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--base',required=True,type=Path);parser.add_argument('--candidate',required=True,type=Path);parser.add_argument('--paths',required=True,type=Path);args=parser.parse_args(argv)
    try:
        base=args.base.resolve(strict=True);candidate=args.candidate.resolve(strict=True)
        if base.is_symlink() or candidate.is_symlink() or not base.is_dir() or not candidate.is_dir():fail('invalid base or candidate root')
        touched=set(lines(args.paths));new_weeks=set();weekly_touched=False
        for value in touched:
            parts=PurePosixPath(value).parts
            if not parts or value.startswith('/') or '\\' in value or any(part in {'','.','..'} for part in parts):fail(f'unsafe changed path: {value}')
            if len(parts)>=2 and parts[:2]==('public','weekly'):
                weekly_touched=True
                if value in MUTABLE:continue
                if len(parts)!=4 or parts[2] in {'index.json','latest.json'} or parts[3] not in WEEK_FILES:fail(f'invalid weekly artifact path: {value}')
                week=parts[2];iso_week(week)
                if (base/value).exists() or (base/'public/weekly'/week).exists():fail(f'existing weekly artifact is immutable: {value}')
                if not (candidate/value).is_file():fail(f'new weekly artifact is missing: {value}')
                new_weeks.add(week)
        if weekly_touched:
            if len(new_weeks)!=1:fail('weekly PR must add exactly one new week')
            new_week=next(iter(new_weeks));required=MUTABLE|{f'public/weekly/{new_week}/report.json',f'public/weekly/{new_week}/index.html'}
            if touched!=required:fail('weekly PR must change exactly the bound weekly artifact/pointer/manifest/request paths')
            weekly_root=base/'public/weekly';existing=[]
            if weekly_root.exists():
                if weekly_root.is_symlink() or not weekly_root.is_dir():fail('invalid base weekly root')
                for entry in weekly_root.iterdir():
                    if entry.name in {'index.json','latest.json'}:
                        if entry.is_symlink() or not entry.is_file():fail('invalid base weekly pointer')
                        continue
                    if entry.is_symlink() or not entry.is_dir():fail('unexpected base weekly entry')
                    iso_week(entry.name);existing.append(entry.name)
            if existing and new_week<=max(existing):fail('weekly history must append after the newest base week')
            base_raw=regular_bytes(base/'operator/pr-request.json',2_000_000);candidate_raw=regular_bytes(candidate/'operator/pr-request.json',2_000_000);base_request=strict_json(base_raw);candidate_request=strict_json(candidate_raw)
            if candidate_raw!=canonical(candidate_request):fail('candidate request JSON is not canonical')
            preserved={'base','publication_items','retractions','public_tree_manifest_path','attestation'}
            if any(base_request.get(key)!=candidate_request.get(key) for key in preserved):fail('weekly PR changed preserved request semantics')
            base_schema=base_request.get('schema');base_weeklies=[] if base_schema=='coderisktools.observatory.pr-request.v3' else base_request.get('weekly_reports')
            if base_schema not in {'coderisktools.observatory.pr-request.v3','coderisktools.observatory.pr-request.v4'} or not isinstance(base_weeklies,list):raise ValueError('unsupported base request history')
            candidate_weeklies=candidate_request.get('weekly_reports')
            if not isinstance(candidate_weeklies,list):raise ValueError('candidate weekly history is not an array')
            if candidate_request.get('schema')!='coderisktools.observatory.pr-request.v4' or candidate_weeklies[:-1]!=base_weeklies or len(candidate_weeklies)!=len(base_weeklies)+1:fail('weekly request history is not a single exact append')
            if not isinstance(candidate_weeklies[-1],dict) or candidate_weeklies[-1].get('week')!=new_week or candidate_request.get('branch')!=f'weekly/{new_week}':fail('weekly request append identity mismatch')
        print(f'WEEKLY_IMMUTABILITY_OK: weeks={len(new_weeks)} paths={len(touched)}');return 0
    except (OSError,UnicodeDecodeError,ValueError) as exc:
        print(f'WEEKLY_IMMUTABILITY_FAILED: {exc}',file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
