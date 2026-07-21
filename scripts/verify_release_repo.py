#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import html
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

HEX64=re.compile(r'^[0-9a-f]{64}$')
ITEM_KEYS={'owner','repository','head_commit','report_revision','observation_id','approval','approval_record_sha256','payload_sha256','bundle_sha256','requested_state'}
REQUEST_KEYS={'schema','base','branch','publication_items','retractions','public_tree_manifest_path','public_tree_manifest_sha256','public_tree_file_count','attestation'}
REQUEST_V4_KEYS=REQUEST_KEYS|{'weekly_reports'}
WEEKLY_BINDING_KEYS={'week','report_sha256','html_sha256'}
WEEKLY_REPORT_KEYS={'schema','week','period','projects','engines','isolation','publication','result','limitations'}
WEEKLY_PROJECT_KEYS={'name','url','license_spdx','review_status'}
WEEKLY_LIMITATIONS=[
    'Project names identify public open-source repositories included in this weekly review index.',
    'Inclusion does not indicate a vulnerability, endorsement, certification, ranking, or accusation.',
    'Technical findings, paths, snippets, rules, secrets, and exact results are not published.',
    'Project names and links are used nominatively to identify the reviewed public repositories.',
]
WEEKLY_SCANNERS={'3.0.0'}
WEEKLY_FIREWALLS={'4.3.0'}
APPROVAL_KEYS={'schema','observation_id','approval','repository','source','publication','files','payload_sha256'}
RETRACTION_KEYS={'schema','observation_id','approval','target','reason_code','retracted_at'}
RETRACTION_REQUEST_KEYS={'target','approval','reason_code','retracted_at','retraction_record_sha256'}
TARGET_KEYS={'owner','repository','head_commit','report_revision','payload_sha256','approval_record_sha256'}
REASONS={'MAINTAINER_REQUEST','SENSITIVE_DATA','INCORRECT_REPORT','LEGAL_REQUEST','POLICY_ERROR'}
REPORT_KEYS={'schema_version','report_id','report_revision','repository','head_commit','scanner_status','firewall_status','publication_status','limitations'}
SCANNER_STATUSES={'SCANNER_NO_MATCHES_IN_TESTED_SCOPE','SCANNER_MATCHES_REDACTED'}
FIREWALL_STATUSES={'FIREWALL_ALLOW','FIREWALL_BLOCKED','FIREWALL_SIMULATION_ALLOW','FIREWALL_SIMULATION_BLOCKED','FIREWALL_NOT_EVALUATED'}
PUBLIC_STATUSES={'PUBLIC','RESOLVED_AND_PUBLISHED'}
SAFE_TEXT=re.compile(r'^[^\x00-\x1f\x7f]{1,200}$')
PRIVATE=(
    re.compile(br'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',re.I),
    re.compile(br'\bAuthorization\s*[:=]\s*(?!\[REDACTED\])\S+',re.I),
    re.compile(br'\bBasic\s+[A-Za-z0-9+/]{8,}={0,2}(?=$|[^A-Za-z0-9+/=])',re.I),
    re.compile(br'\bgh[pousr]_[A-Za-z0-9]{20,}\b'),
    re.compile(br'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(br'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b'),
    re.compile(br'\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret)\s*[:=]\s*(?!\[REDACTED\])[^\s,;]{4,}',re.I),
    re.compile(br'"(?:matched_text|raw_value|secret_value)"\s*:',re.I),
    re.compile(br'\x1b'),
)

class VerificationError(ValueError):pass

def fail(message:str):raise VerificationError(message)
def sha(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def unique(pairs):
    value={}
    for key,item in pairs:
        if key in value:fail(f'duplicate JSON key: {key}')
        value[key]=item
    return value
def constant(value):fail(f'non-finite JSON value: {value}')
def strict_json(data:bytes):
    try:value=json.loads(data,object_pairs_hook=unique,parse_constant=constant)
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:fail(f'invalid JSON: {exc}')
    if not isinstance(value,dict):fail('JSON root must be an object')
    return value
def exact(value,keys,label):
    if not isinstance(value,dict) or set(value)!=keys:fail(f'{label} keys are not closed')
    return value
def hex64(value,label):
    if not isinstance(value,str) or not HEX64.fullmatch(value):fail(f'invalid {label}')
    return value
def safe_component(value,label):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?',value):fail(f'invalid {label}')
    return value
def regular_bytes(path:Path,maximum:int=20_000_000)->bytes:
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)|getattr(os,'O_CLOEXEC',0)
    try:fd=os.open(path,flags)
    except OSError as exc:fail(f'cannot safely open file {path}: {exc}')
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:fail(f'not a single-link regular file: {path}')
        if info.st_size>maximum:fail(f'oversized file: {path}')
        chunks=[];total=0
        while True:
            chunk=os.read(fd,min(65_536,maximum+1-total))
            if not chunk:break
            total+=len(chunk)
            if total>maximum:fail(f'oversized file: {path}')
            chunks.append(chunk)
        data=b''.join(chunks);after=os.fstat(fd)
        if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(data)!=info.st_size:fail(f'file changed during read: {path}')
        return data
    finally:os.close(fd)
def inventory(root:Path)->dict[str,bytes]:
    if root.is_symlink() or not root.is_dir():fail(f'invalid directory: {root}')
    result={}
    for path in root.rglob('*'):
        if path.is_symlink():fail(f'symlink rejected: {path}')
        if path.is_file():result[path.relative_to(root).as_posix()]=regular_bytes(path)
        elif not path.is_dir():fail(f'special entry rejected: {path}')
    return result
def parse_manifest(raw:bytes)->dict[str,str]:
    try:lines=raw.decode('utf-8').splitlines()
    except UnicodeDecodeError:fail('manifest must be UTF-8')
    declared={};previous=''
    for line in lines:
        match=re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)',line)
        if not match:fail('invalid manifest line')
        digest,name=match.groups();parts=PurePosixPath(name).parts
        if not parts or name.startswith('/') or any(part in {'','.','..'} for part in parts) or '\\' in name:fail('unsafe manifest path')
        if name in declared or (previous and name<=previous):fail('manifest paths must be unique and sorted')
        declared[name]=digest;previous=name
    return declared
def canonical_file_manifest(files:dict[str,str])->bytes:return b''.join(f'{value}  {name}\n'.encode() for name,value in sorted(files.items()))
def canonical(value)->bytes:return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def utc(value,label):
    if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',value):fail(f'invalid {label}')
    try:return datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:fail(f'invalid {label}')
def approval(value,label):
    exact(value,{'id','approved_by','approved_at'},label);hex64(value['id'],f'{label} id')
    if not isinstance(value['approved_by'],str) or not value['approved_by'] or len(value['approved_by'])>200:fail(f'invalid {label} reviewer')
    utc(value['approved_at'],f'{label} timestamp');return value
def badge(label):return f'<svg xmlns="http://www.w3.org/2000/svg" width="190" height="20" role="img" aria-label="CodeRiskTools Report: {label}"><rect width="190" height="20" fill="#334155"/><text x="8" y="14" fill="#fff" font-family="sans-serif" font-size="11">CodeRiskTools Report · {label}</text></svg>'.encode()
def safe_text(value,label):
    if type(value) is not str or not SAFE_TEXT.fullmatch(value):fail(f'invalid {label}')
    return value
def render_html(report):
    title=html.escape(f"CodeRiskTools Report — {report['repository']}");limitations=''.join(f'<li>{html.escape(item)}</li>' for item in report['limitations'])
    return f"<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'\"><title>{title}</title></head><body><h1>{title}</h1><p>Commit: <code>{html.escape(report['head_commit'])}</code></p><p>Scanner: {html.escape(report['scanner_status'])}</p><p>Firewall: {html.escape(report['firewall_status'])}</p><h2>Limitations</h2><ul>{limitations}</ul></body></html>".encode()
def render_weekly_html(report):
    week=report['week'];scanner=report['engines']['scanner'];firewall=report['engines']['firewall'];names=[project['name'] for project in report['projects']];joined=', '.join(names);title=f'Open Source Security Review: {joined} — CodeRiskTools Weekly';description=f'CodeRiskTools weekly static review index for {joined}. No project-level vulnerability conclusion or technical findings are published.';projects=''.join(f'<li><a href="{html.escape(project["url"],quote=True)}" rel="noopener noreferrer">{html.escape(project["name"])}</a> — SPDX {html.escape(project["license_spdx"])}, review completed</li>' for project in report['projects']);limitations=''.join(f'<li>{html.escape(item)}</li>' for item in report['limitations'])
    return f"<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'\"><meta name=\"description\" content=\"{html.escape(description,quote=True)}\"><title>{html.escape(title)}</title></head><body><h1>{html.escape(title)}</h1><p>Week: <code>{week}</code></p><p>CodeRiskTools completed a non-executing static review workflow for the named public open-source repositories below.</p><ul>{projects}</ul><p>Engines: Secret Scanner {scanner}; AI Change Firewall {firewall}.</p><p>Isolation: worker network disabled; target code not executed.</p><p><strong>Inclusion does not mean that a vulnerability was found and is not a security certification or ranking.</strong></p><h2>Publication boundary</h2><p>Technical findings and exact project-level results are not published.</p><h2>Limitations</h2><ul>{limitations}</ul></body></html>".encode()
def iso_week(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-W\d{2}',value):fail('invalid weekly report week')
    try:start=datetime.strptime(value+'-1','%G-W%V-%u').date()
    except ValueError as exc:raise VerificationError('invalid weekly report week') from exc
    if start.strftime('%G-W%V')!=value:fail('non-canonical weekly report week')
    return start
def calendar_date(value,label):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}',value):fail(f'invalid {label}')
    try:return date.fromisoformat(value)
    except ValueError:fail(f'invalid {label}')
def validate_weekly_report(raw,html_raw,expected_week):
    if len(raw)>8_192 or len(html_raw)>16_384:fail('oversized weekly artifact')
    report=exact(strict_json(raw),WEEKLY_REPORT_KEYS,'weekly report')
    if raw!=canonical(report):fail('weekly report JSON is not canonical')
    if report['schema']!='coderisktools.observatory.named-weekly-review.v1' or report['week']!=expected_week:fail('weekly review identity mismatch')
    start=iso_week(report['week']);period=exact(report['period'],{'start','end'},'weekly period')
    if calendar_date(period['start'],'weekly period start')!=start or calendar_date(period['end'],'weekly period end')!=start+timedelta(days=6):fail('weekly period does not match ISO week')
    projects=report['projects']
    if not isinstance(projects,list) or len(projects)!=3:fail('named weekly review requires exactly three projects')
    names=[]
    for project in projects:
        project=exact(project,WEEKLY_PROJECT_KEYS,'weekly project');name=project['name']
        if type(name) is not str or len(name)>140 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}',name):fail('invalid weekly project name')
        if project['url']!=f'https://github.com/{name}':fail('weekly project URL is not exact official repository URL')
        license_spdx=project['license_spdx']
        if type(license_spdx) is not str or not re.fullmatch(r'[A-Za-z0-9.+-]{1,100}',license_spdx) or license_spdx in {'NONE','NOASSERTION'}:fail('invalid weekly project SPDX license')
        if project['review_status']!='REVIEW_COMPLETED':fail('weekly project review is incomplete')
        names.append(name)
    if len({name.casefold() for name in names})!=3 or names!=sorted(names,key=str.casefold):fail('weekly projects must be unique and canonically sorted')
    engines=exact(report['engines'],{'scanner','firewall'},'weekly engines')
    if engines['scanner'] not in WEEKLY_SCANNERS or engines['firewall'] not in WEEKLY_FIREWALLS:fail('weekly engine version is not allowlisted')
    isolation=exact(report['isolation'],{'worker_network','target_code_executed'},'weekly isolation')
    if isolation['worker_network']!='NONE' or isolation['target_code_executed'] is not False:fail('invalid weekly isolation truth')
    publication=exact(report['publication'],{'project_names','technical_findings','exact_results','project_level_conclusion'},'weekly publication boundary')
    if publication!={'project_names':'PUBLISHED_FOR_EDITORIAL_INDEXING','technical_findings':'NOT_PUBLISHED','exact_results':'NOT_PUBLISHED','project_level_conclusion':'NONE'}:fail('invalid named weekly publication boundary')
    if report['result']!='NAMED_PROJECT_REVIEWS_COMPLETED_NO_PROJECT_LEVEL_SECURITY_CONCLUSION' or report['limitations']!=WEEKLY_LIMITATIONS:fail('invalid weekly result or limitations')
    if html_raw!=render_weekly_html(report):fail('weekly HTML is not exact deterministic rendering')
    return report
def validate_history(pairs):
    by_head={};by_repo={};identity_by_id={};identity_by_name={}
    for item,record in pairs:
        repository=record['repository'];github_id=repository['github_id'];exact_identity=(item['owner'],item['repository']);canonical_identity=(item['owner'].casefold(),item['repository'].casefold())
        if (github_id in identity_by_id and identity_by_id[github_id]!=exact_identity) or (canonical_identity in identity_by_name and identity_by_name[canonical_identity]!=(github_id,exact_identity)):fail('ambiguous GitHub repository identity')
        identity_by_id[github_id]=exact_identity;identity_by_name[canonical_identity]=(github_id,exact_identity);by_head.setdefault((*exact_identity,item['head_commit']),[]).append((item,record));by_repo.setdefault(exact_identity,[]).append((item,record))
    for group in by_head.values():
        ordered=sorted(group,key=lambda pair:pair[0]['report_revision']);revisions=[pair[0]['report_revision'] for pair in ordered]
        if revisions!=list(range(1,max(revisions)+1)):fail('report revisions must be contiguous from one')
        approvals=[pair[0]['approval']['approved_at'] for pair in ordered]
        if approvals!=sorted(approvals) or len(approvals)!=len(set(approvals)):fail('correction approvals must be strictly monotonic')
        if len({pair[0]['observation_id'] for pair in ordered})!=1:fail('corrections must retain observation identity')
        if len({(pair[1]['source']['base_commit'],pair[1]['source']['head_commit'],pair[1]['source']['source_archive_sha256']) for pair in ordered})!=1:fail('corrections must retain source identity')
    for group in by_repo.values():
        repository_records={canonical(pair[1]['repository']) for pair in group};approvals=[pair[0]['approval']['approved_at'] for pair in group]
        if len(repository_records)!=1:fail('repository metadata changed across publication set')
        if len(approvals)!=len(set(approvals)):fail('publication approval times must be unique per repository')
def validate_report_contract(item,record,public_files,prefix):
    report=exact(strict_json(public_files[prefix+'report.json']),REPORT_KEYS,'report')
    if report['schema_version']!='1.0' or report['report_revision']!=item['report_revision'] or report['repository']!=f"{item['owner']}/{item['repository']}" or report['head_commit']!=item['head_commit']:fail('report metadata mismatch')
    safe_text(report['report_id'],'report id')
    if report['scanner_status'] not in SCANNER_STATUSES or report['firewall_status'] not in FIREWALL_STATUSES or report['publication_status']!=record['publication']['disclosure_status'] or report['publication_status'] not in PUBLIC_STATUSES:fail('invalid report status')
    if type(report['limitations']) is not list or not 1<=len(report['limitations'])<=20 or any(type(value) is not str or not SAFE_TEXT.fullmatch(value) for value in report['limitations']):fail('invalid report limitations')
    scanner=exact(strict_json(public_files[prefix+'scanner-summary.json']),{'status','finding_count','evidence'},'scanner summary')
    if scanner['status']!=report['scanner_status'] or type(scanner['finding_count']) is not int or scanner['finding_count']<0 or type(scanner['evidence']) is not list or scanner['finding_count']!=len(scanner['evidence']):fail('invalid scanner summary')
    if (scanner['status']=='SCANNER_NO_MATCHES_IN_TESTED_SCOPE' and scanner['finding_count']!=0) or (scanner['status']=='SCANNER_MATCHES_REDACTED' and scanner['finding_count']<1):fail('invalid scanner status cardinality')
    for evidence in scanner['evidence']:
        evidence=exact(evidence,{'rule_id','category','path','line','evidence'},'scanner evidence');safe_text(evidence['rule_id'],'rule id');safe_text(evidence['category'],'category');path=safe_text(evidence['path'],'evidence path');pure=PurePosixPath(path)
        if pure.is_absolute() or '..' in pure.parts or '\\' in path or type(evidence['line']) is not int or evidence['line']<1 or evidence['evidence']!='[REDACTED]':fail('unsafe or unredacted scanner evidence')
    firewall=exact(strict_json(public_files[prefix+'firewall-decision.json']),{'status','reasons'},'firewall decision')
    if firewall['status']!=report['firewall_status'] or type(firewall['reasons']) is not list or any(type(value) is not str or not SAFE_TEXT.fullmatch(value) for value in firewall['reasons']):fail('invalid firewall decision')
    markdown=public_files[prefix+'report.md']
    if len(markdown)>1_000_000 or b'\x00' in markdown or re.search(br'<\s*[A-Za-z!/][^>]*>',markdown) or b'javascript:' in markdown.lower():fail('unsafe report markdown')
    try:text=markdown.decode('utf-8')
    except UnicodeDecodeError:fail('report markdown is not UTF-8')
    if any(value not in text for value in ('No scanner matches in the tested scope does not establish that the repository is secure.','A BLOCKED firewall result indicates a mismatch')):fail('required disclaimers missing')
    if public_files.get(prefix+'index.html')!=render_html(report):fail('rendered HTML is not exact approved-report rendering')
def verify_archive(raw,expected):
    try:
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            members=archive.getmembers()
            if [member.name for member in members]!=sorted(expected):fail('bundle members are not exact and sorted')
            for member in members:
                if not member.isfile() or member.size!=len(expected[member.name]) or member.uid!=0 or member.gid!=0 or member.mtime!=0 or member.mode!=0o644 or member.uname or member.gname:fail('bundle metadata or size is not deterministic')
                stream=archive.extractfile(member)
                if stream is None or stream.read()!=expected[member.name]:fail('bundle member byte mismatch')
    except (tarfile.TarError,OSError,EOFError) as exc:fail(f'invalid bundle: {exc}')

def verify(root:Path)->dict:
    root=root.resolve(strict=True);public=root/'public';operator=root/'operator'
    public_files=inventory(public);manifest=public_files.pop('SHA256SUMS.txt',None)
    if manifest is None:fail('missing public manifest')
    declared=parse_manifest(manifest)
    if set(declared)!=set(public_files):fail('public manifest does not close tree')
    for name,expected in declared.items():
        if sha(public_files[name])!=expected:fail(f'public digest mismatch: {name}')
    operator_files=inventory(operator);request_raw=operator_files.pop('pr-request.json',None)
    if request_raw is None:raise VerificationError('missing pr-request.json')
    request=strict_json(request_raw)
    if request_raw!=canonical(request):fail('request JSON is not canonical')
    request_schema=request.get('schema');weekly_reports=[]
    if request_schema=='coderisktools.observatory.pr-request.v3':
        exact(request,REQUEST_KEYS,'request')
    elif request_schema=='coderisktools.observatory.pr-request.v4':
        exact(request,REQUEST_V4_KEYS,'request');weekly_reports=request['weekly_reports']
        if not isinstance(weekly_reports,list) or not weekly_reports or len(weekly_reports)>520:fail('invalid weekly request array')
    else:fail('unsupported request identity')
    if request['base']!='main':fail('unsupported request base')
    if request['public_tree_manifest_path']!='SHA256SUMS.txt' or request['public_tree_manifest_sha256']!=sha(manifest) or request['public_tree_file_count']!=len(public_files):fail('public tree request binding mismatch')
    if request['attestation']!='NOT_GENERATED_REQUIRES_PROTECTED_OIDC_WORKFLOW':fail('invalid pre-attestation state')
    items=request['publication_items'];withdrawals=request['retractions']
    if not isinstance(items,list) or not items or not isinstance(withdrawals,list):fail('invalid request arrays')
    expected_operator=set();item_by_key={};record_by_key={};history_pairs=[];expected_public={'feeds/reports.json','feeds/reports.xml'}
    status_names={'status/status.json','status/index.html'}
    status_present=status_names & set(public_files)
    if status_present and status_present != status_names:fail('status artifact pair is incomplete')
    if status_present:
        expected_public.update(status_names)
        status_payload=strict_json(public_files['status/status.json'])
        exact(status_payload,{'schema_version','generated_at','last_build_sha','last_publication','publication_scope','counts','feeds','self_scan','benchmark'},'status')
        if status_payload['schema_version']!='1.0' or status_payload['publication_scope'] not in {'empty','synthetic','real','mixed'}:fail('invalid status identity')
        if not isinstance(status_payload['generated_at'],str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',status_payload['generated_at']):fail('invalid status timestamp')
        if not isinstance(status_payload['last_build_sha'],str) or not re.fullmatch(r'[0-9a-f]{40}',status_payload['last_build_sha']):fail('invalid status build SHA')
        counts=exact(status_payload['counts'],{'reports','digests','retractions','partial_scans'},'status counts')
        if any(type(value) is not int or value<0 for value in counts.values()):fail('invalid status counts')
        feeds=exact(status_payload['feeds'],{'status'},'status feeds')
        if feeds['status'] not in {'healthy','degraded','unknown'}:fail('invalid status feed')
        self_scan=exact(status_payload['self_scan'],{'decision','finding_count'},'status self-scan')
        if self_scan['decision'] not in {'PUBLISH','HOLD','REJECT'} or type(self_scan['finding_count']) is not int or self_scan['finding_count']<0:fail('invalid status self-scan')
        benchmark=exact(status_payload['benchmark'],{'passed'},'status benchmark')
        if type(benchmark['passed']) is not bool:fail('invalid status benchmark')
        if status_payload['last_publication'] is not None and not isinstance(status_payload['last_publication'],str):fail('invalid status publication timestamp')
        if b'Content-Security-Policy' not in public_files['status/index.html']:fail('status HTML lacks CSP')

    for item in items:
        exact(item,ITEM_KEYS,'publication item');owner=safe_component(item['owner'],'owner');repository=safe_component(item['repository'],'repository');head=item['head_commit']
        if not isinstance(head,str) or not re.fullmatch(r'[0-9a-f]{40}',head):fail('head commit must be full lowercase SHA-1')
        revision=item['report_revision']
        if type(revision) is not int or revision<1:fail('invalid report revision')
        key=(owner,repository,head,revision)
        if key in item_by_key:fail('duplicate publication key')
        item_by_key[key]=item;hex64(item['observation_id'],'observation id');approval_sha=hex64(item['approval_record_sha256'],'approval record digest');payload=hex64(item['payload_sha256'],'payload digest');approval(item['approval'],'approval')
        record_name=f'approval-records/{approval_sha}.json';expected_operator.add(record_name);record_raw=operator_files.get(record_name)
        if record_raw is None or sha(record_raw)!=approval_sha:fail('approval record missing or digest mismatch')
        record=exact(strict_json(record_raw),APPROVAL_KEYS,'approval record')
        if record['schema']!='coderisktools.observatory.approved-publication.v1' or record['observation_id']!=item['observation_id'] or record['approval']!=item['approval'] or record['payload_sha256']!=payload:fail('approval record semantic mismatch')
        repository_record=exact(record['repository'],{'owner','name','github_id','license_spdx'},'repository record');source=exact(record['source'],{'base_commit','head_commit','source_archive_sha256'},'source record');publication=exact(record['publication'],{'disclosure_status','report_revision','maintainer_reviewed'},'publication record')
        if type(repository_record['github_id']) is not int or repository_record['github_id']<1 or repository_record['owner']!=owner or repository_record['name']!=repository or source['head_commit']!=head or publication['report_revision']!=revision or publication['disclosure_status'] not in PUBLIC_STATUSES or publication['maintainer_reviewed'] is not True:fail('approval target mismatch')
        if source['base_commit'] is not None and (type(source['base_commit']) is not str or not re.fullmatch(r'[0-9a-f]{40}',source['base_commit'])):fail('invalid base commit')
        hex64(source['source_archive_sha256'],'source archive digest');safe_text(repository_record['license_spdx'],'license');record_by_key[key]=record;history_pairs.append((item,record))
        files=record['files']
        if not isinstance(files,dict) or set(files)!={'report.md','report.json','scanner-summary.json','firewall-decision.json'} or any(type(value) is not str or not HEX64.fullmatch(value) for value in files.values()):fail('invalid approval file map')
        if sha(canonical_file_manifest(files))!=payload:fail('approval payload digest mismatch')
        report_prefix=f'reports/github/{owner}/{repository}/{head}/r{revision}/'
        state=item['requested_state']
        if state=='AVAILABLE':
            bundle=hex64(item['bundle_sha256'],'bundle digest')
            for name,expected in files.items():
                public_name=report_prefix+name
                if public_name not in public_files or sha(public_files[public_name])!=expected:fail('approved public report byte mismatch')
            checks_name=report_prefix+'checksums.txt';bundle_name=report_prefix+'report.tar.gz'
            if public_files.get(checks_name)!=canonical_file_manifest(files) or bundle_name not in public_files or sha(public_files[bundle_name])!=bundle:fail('report checksums or bundle mismatch')
            archive_files={name:public_files[report_prefix+name] for name in files};archive_files['checksums.txt']=public_files[checks_name];verify_archive(public_files[bundle_name],archive_files);validate_report_contract(item,record,public_files,report_prefix)
            expected_public.update({report_prefix+name for name in (*files,'checksums.txt','report.tar.gz','index.html')})
        elif state=='WITHDRAWN':
            if item['bundle_sha256'] is not None:fail('withdrawn item retains bundle digest')
            actual={name.removeprefix(report_prefix) for name in public_files if name.startswith(report_prefix)}
            if actual!={'index.html','retraction.json'}:fail('withdrawn target is not a neutral tombstone')
            expected_public.update({report_prefix+'index.html',report_prefix+'retraction.json'})
        else:fail('invalid requested state')
    validate_history(history_pairs)
    seen_withdrawals=set()
    for withdrawal in withdrawals:
        exact(withdrawal,RETRACTION_REQUEST_KEYS,'retraction request');target=exact(withdrawal['target'],TARGET_KEYS,'retraction target');key=(target['owner'],target['repository'],target['head_commit'],target['report_revision'])
        if key in seen_withdrawals or key not in item_by_key or item_by_key[key]['requested_state']!='WITHDRAWN':fail('invalid retraction target')
        item=item_by_key[key];expected_target={'owner':item['owner'],'repository':item['repository'],'head_commit':item['head_commit'],'report_revision':item['report_revision'],'payload_sha256':item['payload_sha256'],'approval_record_sha256':item['approval_record_sha256']}
        if target!=expected_target:fail('retraction target does not bind publication item')
        seen_withdrawals.add(key);record_sha=hex64(withdrawal['retraction_record_sha256'],'retraction record digest');record_name=f'retraction-records/{record_sha}.json';expected_operator.add(record_name);raw=operator_files.get(record_name)
        if raw is None or sha(raw)!=record_sha:fail('retraction record missing or digest mismatch')
        record=exact(strict_json(raw),RETRACTION_KEYS,'retraction record')
        if record['schema']!='coderisktools.observatory.retraction.v1' or record['target']!=target or record['approval']!=withdrawal['approval'] or record['reason_code']!=withdrawal['reason_code'] or record['retracted_at']!=withdrawal['retracted_at']:fail('retraction semantic mismatch')
        if record['observation_id']!=item['observation_id'] or record['reason_code'] not in REASONS:fail('invalid retraction observation or reason')
        approval(record['approval'],'retraction approval');target_time=utc(item['approval']['approved_at'],'target approval timestamp');retraction_approval_time=utc(record['approval']['approved_at'],'retraction approval timestamp');retracted_time=utc(record['retracted_at'],'retracted timestamp')
        if record['approval']['id']==item['approval']['id'] or not target_time<=retraction_approval_time<=retracted_time:fail('invalid retraction approval or chronology')
        prefix=f"reports/github/{target['owner']}/{target['repository']}/{target['head_commit']}/r{target['report_revision']}/";tombstone={'schema_version':'1.0','status':'WITHDRAWN','repository':f"{target['owner']}/{target['repository']}",'head_commit':target['head_commit'],'report_revision':target['report_revision'],'retracted_at':record['retracted_at'],'message':'This report has been withdrawn and is unavailable.'};tombstone_html=("<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; base-uri 'none'; form-action 'none'\"><title>Report unavailable</title></head><body><h1>Report unavailable</h1><p>This report has been withdrawn and is unavailable.</p></body></html>").encode()
        if public_files.get(prefix+'retraction.json')!=canonical(tombstone) or public_files.get(prefix+'index.html')!=tombstone_html:fail('public retraction tombstone is not exact and neutral')
    if {key for key,item in item_by_key.items() if item['requested_state']=='WITHDRAWN'}!=seen_withdrawals:fail('withdrawn item lacks retraction')
    if set(operator_files)!=expected_operator:fail('operator tree has missing or unbound records')
    available=[key for key,item in item_by_key.items() if item['requested_state']=='AVAILABLE'];current={}
    for key in available:
        item=item_by_key[key];repo=key[:2];rank=(utc(item['approval']['approved_at'],'approval timestamp'),key[2],key[3])
        if repo not in current or rank>current[repo][0]:current[repo]=(rank,key)
    entries=[];repos=sorted({key[:2] for key in item_by_key})
    for key in available:
        item=item_by_key[key];selected=current[key[:2]][1];lifecycle='CURRENT' if key==selected else 'SUPERSEDED' if key[2]==selected[2] else 'STALE';prefix=f'reports/github/{key[0]}/{key[1]}/{key[2]}/r{key[3]}/';report=strict_json(public_files[prefix+'report.json']);publication_status=report.get('publication_status')
        if publication_status not in PUBLIC_STATUSES:fail('invalid public report status')
        entries.append({'schema_version':'1.0','repository':f'{key[0]}/{key[1]}','head_commit':key[2],'report_revision':key[3],'publication_status':publication_status,'lifecycle_status':lifecycle,'report_path':'/'+prefix,'bundle_sha256':item['bundle_sha256'],'approved_at':item['approval']['approved_at']})
    entries.sort(key=lambda value:(value['approved_at'],value['repository'],value['head_commit'],value['report_revision']),reverse=True)
    if public_files.get('feeds/reports.json')!=canonical({'schema_version':'1.0','reports':entries}):fail('JSON feed semantic mismatch')
    xml_items=''.join(f'<report><repository>{html.escape(value["repository"])}</repository><head>{value["head_commit"]}</head><revision>{value["report_revision"]}</revision><status>{value["lifecycle_status"]}</status><path>{value["report_path"]}</path></report>' for value in entries)
    if public_files.get('feeds/reports.xml')!=f'<?xml version="1.0" encoding="UTF-8"?><feed>{xml_items}</feed>'.encode():fail('XML feed semantic mismatch')
    for owner,repository in repos:
        repo_entries=[value for value in entries if value['repository']==f'{owner}/{repository}'];selected=next((value for value in repo_entries if value['lifecycle_status']=='CURRENT'),None);latest=selected or {'schema_version':'1.0','repository':f'{owner}/{repository}','publication_status':'UNAVAILABLE','lifecycle_status':'UNAVAILABLE','report_path':None};latest_name=f'reports/github/{owner}/{repository}/latest.json';badge_name=f'badges/{owner}/{repository}.svg';expected_public.update({latest_name,badge_name})
        if public_files.get(latest_name)!=canonical(latest):fail('latest pointer semantic mismatch')
        if selected is None:label='Report unavailable'
        else:
            key=current[(owner,repository)][1];prefix=f'reports/github/{owner}/{repository}/{key[2]}/r{key[3]}/';firewall=strict_json(public_files[prefix+'firewall-decision.json']);label='Reviewed' if firewall.get('status') in {'FIREWALL_ALLOW','FIREWALL_SIMULATION_ALLOW'} else 'Report available'
        if public_files.get(badge_name)!=badge(label):fail('badge semantic mismatch')
    weekly_entries=[];previous_week=''
    if weekly_reports:
        newest_binding=weekly_reports[-1]
        if not isinstance(newest_binding,dict) or request['branch']!=f"weekly/{newest_binding.get('week')}":fail('weekly request branch is not bound to newest week')
    for binding in weekly_reports:
        exact(binding,WEEKLY_BINDING_KEYS,'weekly binding');week=binding['week'];iso_week(week)
        if previous_week and week<=previous_week:fail('weekly bindings must be unique and sorted')
        previous_week=week
        report_name=f'weekly/{week}/report.json';html_name=f'weekly/{week}/index.html';report_raw=public_files.get(report_name);html_raw=public_files.get(html_name)
        if report_raw is None or html_raw is None:raise VerificationError('weekly public artifact missing')
        if sha(report_raw)!=hex64(binding['report_sha256'],'weekly report digest') or sha(html_raw)!=hex64(binding['html_sha256'],'weekly HTML digest'):fail('weekly public digest mismatch')
        validate_weekly_report(report_raw,html_raw,week);expected_public.update({report_name,html_name});weekly_entries.append({'week':week,'report_path':f'/weekly/{week}/'})
    if weekly_entries:
        weekly_entries.reverse();index_name='weekly/index.json';latest_name='weekly/latest.json';expected_public.update({index_name,latest_name})
        if public_files.get(index_name)!=canonical({'schema':'coderisktools.observatory.named-weekly-index.v1','reports':weekly_entries}):fail('weekly index semantic mismatch')
        if public_files.get(latest_name)!=canonical(weekly_entries[0]):fail('weekly latest semantic mismatch')
    if set(public_files)!=expected_public:fail('public tree contains unbound semantic artifacts')
    for name,data in public_files.items():
        if not name.endswith('.tar.gz') and (any(pattern.search(data) for pattern in PRIVATE) or b'<script' in data.lower() or b'javascript:' in data.lower()):fail(f'public leakage or active content: {name}')
        if name.endswith('.html') and b'Content-Security-Policy' not in data:fail(f'HTML lacks CSP: {name}')
    return {'public_files':len(public_files),'publication_items':len(items),'retractions':len(withdrawals),'public_manifest_sha256':sha(manifest)}

def main(argv=None)->int:
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True,type=Path);args=parser.parse_args(argv)
    try:result=verify(args.root)
    except (OSError,VerificationError) as exc:print(f'VERIFICATION_FAILED: {exc}',file=sys.stderr);return 2
    print(json.dumps(result,sort_keys=True,separators=(',',':')));return 0

if __name__=='__main__':raise SystemExit(main())
