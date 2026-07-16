#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
_SPEC=importlib.util.spec_from_file_location('weekly_release_verifier',HERE/'verify_release_repo.py')
assert _SPEC is not None and _SPEC.loader is not None
verifier=importlib.util.module_from_spec(_SPEC);_SPEC.loader.exec_module(verifier)
PRIVATE_KEYS={'schema','repository','stars','license_spdx','status','scanner_version','firewall_version','worker_network','target_code_executed'}
PRIVATE_SCHEMA='coderisktools.observatory.private-weekly-trial.v1'

def fail(message):raise ValueError(message)
def private_bytes(path:Path,maximum=100_000):
    parent=path.parent;parent_before=parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(parent_before.st_mode) or parent_before.st_uid!=os.geteuid() or stat.S_IMODE(parent_before.st_mode)!=0o700:fail('private input parent must be owner-controlled mode 0700')
    flags=os.O_RDONLY|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0);fd=os.open(path,flags)
    try:
        before=os.fstat(fd);mode=stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.geteuid() or mode not in {0o400,0o600} or before.st_size>maximum:fail('private input must be owner-only single-link regular file')
        chunks=[];total=0
        while True:
            chunk=os.read(fd,min(65_536,maximum-total+1))
            if not chunk:break
            chunks.append(chunk);total+=len(chunk)
            if total>maximum:fail('private input is oversized')
        after=os.fstat(fd);parent_after=parent.lstat()
        if (before.st_dev,before.st_ino,before.st_size,before.st_mode,before.st_uid,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mode,after.st_uid,after.st_mtime_ns,after.st_ctime_ns) or total!=before.st_size:fail('private input changed during read')
        if (parent_before.st_dev,parent_before.st_ino,parent_before.st_mode,parent_before.st_uid,parent_before.st_ctime_ns)!=(parent_after.st_dev,parent_after.st_ino,parent_after.st_mode,parent_after.st_uid,parent_after.st_ctime_ns):fail('private input parent changed during read')
        return b''.join(chunks)
    finally:os.close(fd)
def read_input(path):
    value=verifier.strict_json(private_bytes(path));verifier.exact(value,PRIVATE_KEYS,'private weekly trial')
    if value['schema']!=PRIVATE_SCHEMA:fail('unsupported private trial schema')
    repository=value['repository']
    if type(repository) is not str or len(repository)>140 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}',repository):fail('invalid private repository identity')
    if type(value['stars']) is not int or value['stars']<10_000:fail('private trial is not in the popular cohort')
    if type(value['license_spdx']) is not str or not re.fullmatch(r'[A-Za-z0-9.+-]{1,100}',value['license_spdx']) or value['license_spdx'] in {'NONE','NOASSERTION'}:fail('private trial lacks SPDX license')
    if value['status']!='COMPLETE' or value['scanner_version'] not in verifier.WEEKLY_SCANNERS or value['firewall_version'] not in verifier.WEEKLY_FIREWALLS:fail('private trial status or engine is ineligible')
    if value['worker_network']!='NONE' or value['target_code_executed'] is not False:fail('private trial isolation is ineligible')
    return value

def copy_tracked(source:Path,destination:Path):
    def command(*args):return subprocess.run(['git','-C',str(source),'-c','core.hooksPath=/dev/null',*args],capture_output=True)
    head_before=command('rev-parse','HEAD').stdout.decode('ascii').strip()
    status=command('status','--porcelain=v1','-z','--untracked-files=all')
    if not re.fullmatch(r'[0-9a-f]{40}',head_before) or status.returncode or status.stdout:fail('source repository must be a clean Git worktree')
    listing=command('ls-tree','-r','-z','--full-tree',head_before)
    if listing.returncode or not listing.stdout:fail('cannot enumerate tracked source tree')
    seen=set();destination.mkdir()
    for entry in listing.stdout.split(b'\0'):
        if not entry:continue
        try:metadata,raw_name=entry.split(b'\t',1);mode,kind,object_id=metadata.decode('ascii').split();name=raw_name.decode('utf-8')
        except (ValueError,UnicodeDecodeError) as exc:raise ValueError('malformed tracked file entry') from exc
        parts=verifier.PurePosixPath(name).parts;portable=name.casefold()
        if mode not in {'100644','100755'} or kind!='blob' or not re.fullmatch(r'[0-9a-f]{40}',object_id) or not parts or name.startswith('/') or '\\' in name or any(part in {'','.','..'} for part in parts) or portable in seen:fail(f'unsafe tracked source file: {name}')
        blob=command('cat-file','blob',object_id)
        if blob.returncode or len(blob.stdout)>20_000_000:fail(f'cannot safely read tracked blob: {name}')
        seen.add(portable);target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(blob.stdout);target.chmod(0o755 if mode=='100755' else 0o644)
    head_after=command('rev-parse','HEAD').stdout.decode('ascii').strip();status_after=command('status','--porcelain=v1','-z','--untracked-files=all')
    if head_after!=head_before or status_after.returncode or status_after.stdout:fail('source repository changed during Git-object snapshot')

def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--source-root',required=True,type=Path);parser.add_argument('--output-root',required=True,type=Path);parser.add_argument('--week',required=True);parser.add_argument('--private-input',required=True,type=Path,action='append');args=parser.parse_args(argv)
    stage_parent=None
    try:
        source=args.source_root.resolve(strict=True);output=args.output_root.absolute()
        if source.is_symlink() or not source.is_dir() or output.exists() or output==source or source in output.parents:fail('source/output boundary is invalid')
        if len(args.private_input)!=3:fail('named weekly review requires exactly three project trials')
        if any(path.is_symlink() for path in args.private_input):fail('private trial input symlink is forbidden')
        input_paths=[path.resolve(strict=True) for path in args.private_input]
        if any(path==source or source in path.parents for path in input_paths):fail('private trial input must remain outside source repository')
        inputs=[read_input(path) for path in input_paths];identities=[value['repository'] for value in inputs]
        if len({value.casefold() for value in identities})!=len(identities):fail('private weekly cohort repositories must be unique')
        engine_pairs={(value['scanner_version'],value['firewall_version']) for value in inputs}
        if len(engine_pairs)!=1:fail('private weekly cohort must use one engine pair')
        start=verifier.iso_week(args.week);end=start+verifier.timedelta(days=6);scanner,firewall=next(iter(engine_pairs))
        output.parent.mkdir(parents=True,exist_ok=True);stage_parent=Path(tempfile.mkdtemp(prefix='.weekly-build-',dir=output.parent));stage=stage_parent/'candidate';copy_tracked(source,stage)
        public=stage/'public';operator=stage/'operator';request_path=operator/'pr-request.json';request=verifier.strict_json(verifier.regular_bytes(request_path));bindings=[]
        schema=request.get('schema')
        if schema=='coderisktools.observatory.pr-request.v3':verifier.exact(request,verifier.REQUEST_KEYS,'request')
        elif schema=='coderisktools.observatory.pr-request.v4':verifier.exact(request,verifier.REQUEST_V4_KEYS,'request');bindings=list(request['weekly_reports'])
        else:fail('unsupported source request schema')
        if any(binding.get('week')==args.week for binding in bindings):fail('weekly report already exists')
        projects=sorted(({'name':value['repository'],'url':f"https://github.com/{value['repository']}",'license_spdx':value['license_spdx'],'review_status':'REVIEW_COMPLETED'} for value in inputs),key=lambda project:project['name'].casefold())
        report={
            'schema':'coderisktools.observatory.named-weekly-review.v1','week':args.week,
            'period':{'start':start.isoformat(),'end':end.isoformat()},
            'projects':projects,
            'engines':{'scanner':scanner,'firewall':firewall},
            'isolation':{'worker_network':'NONE','target_code_executed':False},
            'publication':{'project_names':'PUBLISHED_FOR_EDITORIAL_INDEXING','technical_findings':'NOT_PUBLISHED','exact_results':'NOT_PUBLISHED','project_level_conclusion':'NONE'},
            'result':'NAMED_PROJECT_REVIEWS_COMPLETED_NO_PROJECT_LEVEL_SECURITY_CONCLUSION','limitations':verifier.WEEKLY_LIMITATIONS,
        }
        report_raw=verifier.canonical(report);html_raw=verifier.render_weekly_html(report);week_dir=public/'weekly'/args.week;week_dir.mkdir(parents=True,exist_ok=False);(week_dir/'report.json').write_bytes(report_raw);(week_dir/'index.html').write_bytes(html_raw)
        bindings.append({'week':args.week,'report_sha256':verifier.sha(report_raw),'html_sha256':verifier.sha(html_raw)});bindings.sort(key=lambda value:value['week'])
        entries=[{'week':binding['week'],'report_path':f"/weekly/{binding['week']}/"} for binding in reversed(bindings)];weekly=public/'weekly';(weekly/'index.json').write_bytes(verifier.canonical({'schema':'coderisktools.observatory.named-weekly-index.v1','reports':entries}));(weekly/'latest.json').write_bytes(verifier.canonical(entries[0]))
        weekly_bytes=b''.join((week_dir/name).read_bytes().lower() for name in ('report.json','index.html'))
        if any(identity.casefold().encode() not in weekly_bytes for identity in identities):fail('approved project identity missing from named weekly bytes')
        request['schema']='coderisktools.observatory.pr-request.v4';request['branch']=f'weekly/{args.week}';request['weekly_reports']=bindings
        public_files=verifier.inventory(public);public_files.pop('SHA256SUMS.txt',None);manifest=verifier.canonical_file_manifest({name:verifier.sha(data) for name,data in public_files.items()});(public/'SHA256SUMS.txt').write_bytes(manifest)
        request['public_tree_manifest_sha256']=verifier.sha(manifest);request['public_tree_file_count']=len(public_files);request_path.write_bytes(verifier.canonical(request))
        result=verifier.verify(stage);os.replace(stage,output);stage_parent.rmdir();stage_parent=None
        print(json.dumps({'week':args.week,'private_trials':len(inputs),'output':str(output),'verification':result},sort_keys=True,separators=(',',':')));return 0
    except (OSError,ValueError,verifier.VerificationError) as exc:
        print(f'WEEKLY_BUILD_FAILED: {exc}',file=__import__('sys').stderr);return 2
    finally:
        if stage_parent is not None:shutil.rmtree(stage_parent,ignore_errors=True)

if __name__=='__main__':raise SystemExit(main())
