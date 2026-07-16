#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

WEEK_PATH=re.compile(r'^public/weekly/(\d{4}-W\d{2})/(?:report\.json|index\.html)$')
PR_BODY='Publishes one verified named OSS review index. Technical findings and project-level security conclusions are not published.'
IDENTITY=('9batalion','38577463+9batalion@users.noreply.github.com','9batalion','38577463+9batalion@users.noreply.github.com')

def fail(message):raise ValueError(message)
def path_lines(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>1_000_000:fail('invalid changed-path list')
    raw=path.read_bytes();values=raw.decode('utf-8').splitlines()
    if path.lstat().st_size!=len(raw) or not values or len(values)!=len(set(values)):fail('changed-path list changed, empty, or duplicate')
    return values

def git(candidate,*args):
    result=subprocess.run(['git','-C',str(candidate),'-c','core.hooksPath=/dev/null',*args],capture_output=True)
    if result.returncode:fail('Git metadata query failed')
    return result.stdout

def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--candidate',required=True,type=Path);parser.add_argument('--paths',required=True,type=Path);args=parser.parse_args(argv)
    try:
        candidate=args.candidate.resolve(strict=True);values=path_lines(args.paths);weeks={match.group(1) for value in values if (match:=WEEK_PATH.fullmatch(value))}
        if not weeks:
            print('WEEKLY_PR_METADATA_OK: not-weekly');return 0
        if len(weeks)!=1:fail('weekly PR metadata has ambiguous week')
        week=next(iter(weeks))
        base=os.environ.get('BASE_SHA','');title=os.environ.get('PR_TITLE');body=os.environ.get('PR_BODY');head_ref=os.environ.get('HEAD_REF')
        if not re.fullmatch(r'[0-9a-f]{40}',base):fail('invalid base SHA')
        expected_public_metadata={'PR_AUTHOR':'9batalion','PR_DRAFT':'false','PR_LABELS':'[]','PR_ASSIGNEES':'[]','PR_REVIEWERS':'[]','PR_TEAMS':'[]','PR_MILESTONE':'null'}
        if any(os.environ.get(key)!=expected for key,expected in expected_public_metadata.items()):fail('weekly PR auxiliary metadata is not empty/exact')
        expected_title=f'Named OSS weekly review {week}'
        if title!=expected_title or body!=PR_BODY or head_ref!=f'weekly/{week}':fail('weekly PR title, body, or head ref is not exact')
        if subprocess.run(['git','-C',str(candidate),'merge-base','--is-ancestor',base,'HEAD'],capture_output=True).returncode:fail('base is not ancestor of weekly candidate')
        if git(candidate,'rev-list','--count',f'{base}..HEAD').decode().strip()!='1':fail('weekly PR must contain exactly one commit')
        subject=git(candidate,'log','-1','--format=%s').decode().rstrip('\n');commit_body=git(candidate,'log','-1','--format=%b').decode().rstrip('\n')
        if subject!=expected_title or commit_body:fail('weekly commit subject/body is not exact')
        identity=tuple(git(candidate,'log','-1','--format=%an%x00%ae%x00%cn%x00%ce').decode().rstrip('\n').split('\0'))
        if identity!=IDENTITY:fail('weekly commit identity is not exact')
        start=datetime.strptime(week+'-1','%G-W%V-%u').date();epoch=str(int(datetime(start.year,start.month,start.day,8,tzinfo=timezone.utc).timestamp()))
        times=git(candidate,'log','-1','--format=%at%x00%ct').decode().rstrip('\n').split('\0')
        if times!=[epoch,epoch]:fail('weekly commit timestamp is not deterministic')
        tree=git(candidate,'rev-parse','HEAD^{tree}').decode().strip()
        if not re.fullmatch(r'[0-9a-f]{40}',tree):fail('invalid weekly commit tree')
        identity_line=f'9batalion <38577463+9batalion@users.noreply.github.com> {epoch} +0000'
        expected_commit=(f'tree {tree}\nparent {base}\nauthor {identity_line}\ncommitter {identity_line}\n\n{expected_title}\n').encode()
        if git(candidate,'cat-file','commit','HEAD')!=expected_commit:fail('weekly raw commit object is not canonical')
        tree_rows=git(candidate,'ls-tree','-z','HEAD','--',*values).split(b'\0');seen=set()
        for row in tree_rows:
            if not row:continue
            try:metadata,raw_path=row.split(b'\t',1);mode,kind,_object=metadata.decode('ascii').split();path=raw_path.decode('utf-8')
            except (ValueError,UnicodeDecodeError) as exc:raise ValueError('malformed weekly tree entry') from exc
            if mode!='100644' or kind!='blob' or path in seen:fail('weekly changed path mode/type is not canonical')
            seen.add(path)
        if seen!=set(values):fail('weekly changed paths are not exact regular Git blobs')
        print(f'WEEKLY_PR_METADATA_OK: {week}');return 0
    except (OSError,UnicodeDecodeError,ValueError) as exc:
        print(f'WEEKLY_PR_METADATA_FAILED: {exc}',file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
