from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
VERIFY=ROOT/'scripts/verify_release_repo.py'
VERIFY_PATHS=ROOT/'scripts/verify_changed_paths.py'
_SPEC=importlib.util.spec_from_file_location('release_verifier',VERIFY);release_verifier=importlib.util.module_from_spec(_SPEC);assert _SPEC.loader;_SPEC.loader.exec_module(release_verifier)
HEAD='b'*40
SHAS={
    'checkout':'9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0',
    'upload':'fc324d3547104276b827a68afc52ff2a11cc49c9',
    'deploy':'d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e',
    'attest':'977bb373ede98d70efdf65b84cb5f73e068dcc2a',
    'configure':'983d7736d9b0ae728b81ab479565c72886d7745b',
}

def canonical(value)->bytes:return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def digest(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def deterministic_tar(files:dict[str,bytes])->bytes:
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT) as archive:
        for name,data in sorted(files.items()):
            info=tarfile.TarInfo(name);info.size=len(data);info.mtime=0;info.mode=0o644;info.uid=0;info.gid=0;info.uname='';info.gname='';archive.addfile(info,io.BytesIO(data))
    out=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=out,mtime=0) as stream:stream.write(raw.getvalue())
    return out.getvalue()
def badge(label:str)->bytes:return f'<svg xmlns="http://www.w3.org/2000/svg" width="190" height="20" role="img" aria-label="CodeRiskTools Report: {label}"><rect width="190" height="20" fill="#334155"/><text x="8" y="14" fill="#fff" font-family="sans-serif" font-size="11">CodeRiskTools Report · {label}</text></svg>'.encode()

def fixture(root:Path,withdrawn:bool=False,status:str='PUBLIC')->Path:
    public=root/'public';operator=root/'operator';records=operator/'approval-records';retractions=operator/'retraction-records'
    for path in (public/'reports/github/o/r'/HEAD/'r1',public/'feeds',public/'badges/o',records,retractions):path.mkdir(parents=True,exist_ok=True)
    base=public/'reports/github/o/r'/HEAD/'r1';report={'schema_version':'1.0','report_id':'crt-test-1','report_revision':1,'repository':'o/r','head_commit':HEAD,'scanner_status':'SCANNER_NO_MATCHES_IN_TESTED_SCOPE','firewall_status':'FIREWALL_ALLOW','publication_status':status,'limitations':['Tested scope only; this is not a security certification.']};scanner={'status':report['scanner_status'],'finding_count':0,'evidence':[]};firewall={'status':report['firewall_status'],'reasons':['No intent mismatch in tested diff.']};markdown=b'# Report\n\nNo scanner matches in the tested scope does not establish that the repository is secure.\n\nA BLOCKED firewall result indicates a mismatch with the tested intent or named policy profile.\n';source_files={'report.md':markdown,'report.json':canonical(report),'scanner-summary.json':canonical(scanner),'firewall-decision.json':canonical(firewall)};file_hashes={name:digest(data) for name,data in source_files.items()};payload=digest(b''.join(f'{value}  {name}\n'.encode() for name,value in sorted(file_hashes.items())))
    approval={'schema':'coderisktools.observatory.approved-publication.v1','observation_id':'a'*64,'approval':{'id':'b'*64,'approved_by':'reviewer','approved_at':'2026-07-16T12:00:00Z'},'repository':{'owner':'o','name':'r','github_id':1,'license_spdx':'MIT'},'source':{'base_commit':'0'*40,'head_commit':HEAD,'source_archive_sha256':'1'*64},'publication':{'disclosure_status':status,'report_revision':1,'maintainer_reviewed':True},'files':file_hashes,'payload_sha256':payload}
    approval_raw=canonical(approval);approval_sha=digest(approval_raw);(records/f'{approval_sha}.json').write_bytes(approval_raw)
    base=public/'reports/github/o/r'/HEAD/'r1'
    if withdrawn:
        tombstone={'schema_version':'1.0','status':'WITHDRAWN','repository':'o/r','head_commit':HEAD,'report_revision':1,'retracted_at':'2026-07-16T13:01:00Z','message':'This report has been withdrawn and is unavailable.'};(base/'retraction.json').write_bytes(canonical(tombstone));(base/'index.html').write_text('<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'"><title>Report unavailable</title></head><body><h1>Report unavailable</h1><p>This report has been withdrawn and is unavailable.</p></body></html>')
        retract={'schema':'coderisktools.observatory.retraction.v1','observation_id':'a'*64,'target':{'owner':'o','repository':'r','head_commit':HEAD,'report_revision':1,'payload_sha256':payload,'approval_record_sha256':approval_sha},'approval':{'id':'d'*64,'approved_by':'reviewer2','approved_at':'2026-07-16T13:00:00Z'},'reason_code':'MAINTAINER_REQUEST','retracted_at':'2026-07-16T13:01:00Z'}
        retract_raw=canonical(retract);retract_sha=digest(retract_raw);(retractions/f'{retract_sha}.json').write_bytes(retract_raw);bundle=None;state='WITHDRAWN';entries=[];latest={'schema_version':'1.0','repository':'o/r','publication_status':'UNAVAILABLE','lifecycle_status':'UNAVAILABLE','report_path':None};badge_label='Report unavailable'
    else:
        checks=b''.join(f'{value}  {name}\n'.encode() for name,value in sorted(file_hashes.items()));archive_files={**source_files,'checksums.txt':checks};bundle_bytes=deterministic_tar(archive_files)
        for name,data in source_files.items():(base/name).write_bytes(data)
        (base/'index.html').write_bytes(release_verifier.render_html(report));(base/'checksums.txt').write_bytes(checks);(base/'report.tar.gz').write_bytes(bundle_bytes);bundle=digest(bundle_bytes);state='AVAILABLE';retract_sha=None
        latest={'schema_version':'1.0','repository':'o/r','head_commit':HEAD,'report_revision':1,'publication_status':status,'lifecycle_status':'CURRENT','report_path':f'/reports/github/o/r/{HEAD}/r1/','bundle_sha256':bundle,'approved_at':'2026-07-16T12:00:00Z'};entries=[latest];badge_label='Reviewed'
    (public/'reports/github/o/r/latest.json').write_bytes(canonical(latest));(public/'feeds/reports.json').write_bytes(canonical({'schema_version':'1.0','reports':entries}));xml_items=''.join(f'<report><repository>{item["repository"]}</repository><head>{item["head_commit"]}</head><revision>{item["report_revision"]}</revision><status>{item["lifecycle_status"]}</status><path>{item["report_path"]}</path></report>' for item in entries);(public/'feeds/reports.xml').write_text(f'<?xml version="1.0" encoding="UTF-8"?><feed>{xml_items}</feed>');(public/'badges/o/r.svg').write_bytes(badge(badge_label))
    members={p.relative_to(public).as_posix():p.read_bytes() for p in public.rglob('*') if p.is_file()};manifest=b''.join(f'{digest(data)}  {name}\n'.encode() for name,data in sorted(members.items()));(public/'SHA256SUMS.txt').write_bytes(manifest)
    item={'owner':'o','repository':'r','head_commit':HEAD,'report_revision':1,'observation_id':'a'*64,'approval':approval['approval'],'approval_record_sha256':approval_sha,'payload_sha256':payload,'bundle_sha256':bundle,'requested_state':state}
    request={'schema':'coderisktools.observatory.pr-request.v3','base':'main','branch':'reports/test','publication_items':[item],'retractions':([] if retract_sha is None else [{'target':retract['target'],'approval':retract['approval'],'reason_code':'MAINTAINER_REQUEST','retracted_at':'2026-07-16T13:01:00Z','retraction_record_sha256':retract_sha}]),'public_tree_manifest_path':'SHA256SUMS.txt','public_tree_manifest_sha256':digest(manifest),'public_tree_file_count':len(members),'attestation':'NOT_GENERATED_REQUIRES_PROTECTED_OIDC_WORKFLOW'}
    (operator/'pr-request.json').write_bytes(canonical(request));return root

def rebind_public(root:Path)->None:
    public=root/'public';members={p.relative_to(public).as_posix():p.read_bytes() for p in public.rglob('*') if p.is_file() and p.name!='SHA256SUMS.txt'};manifest=b''.join(f'{digest(data)}  {name}\n'.encode() for name,data in sorted(members.items()));(public/'SHA256SUMS.txt').write_bytes(manifest);request=json.loads((root/'operator/pr-request.json').read_text());request['public_tree_manifest_sha256']=digest(manifest);request['public_tree_file_count']=len(members);(root/'operator/pr-request.json').write_bytes(canonical(request))

def rewrite_retraction(root:Path,mutate)->None:
    records=root/'operator/retraction-records';old=next(records.iterdir());record=json.loads(old.read_text());mutate(record);old.unlink();raw=canonical(record);new_sha=digest(raw);(records/f'{new_sha}.json').write_bytes(raw);request=json.loads((root/'operator/pr-request.json').read_text());entry=request['retractions'][0];entry.update({'target':record['target'],'approval':record['approval'],'reason_code':record['reason_code'],'retracted_at':record['retracted_at'],'retraction_record_sha256':new_sha});(root/'operator/pr-request.json').write_bytes(canonical(request))

class ReleaseRepoTests(unittest.TestCase):
    def run_verify(self,root:Path):return subprocess.run([sys.executable,str(VERIFY),'--root',str(root)],text=True,capture_output=True)
    def test_valid_available_and_withdrawn_repositories_pass(self):
        for withdrawn in (False,True):
            with self.subTest(withdrawn=withdrawn),tempfile.TemporaryDirectory() as value:self.assertEqual(self.run_verify(fixture(Path(value),withdrawn)).returncode,0)
    def test_valid_resolved_and_published_repository_passes(self):
        with tempfile.TemporaryDirectory() as value:self.assertEqual(self.run_verify(fixture(Path(value),status='RESOLVED_AND_PUBLISHED')).returncode,0)
    def test_public_tamper_and_extra_file_fail(self):
        with tempfile.TemporaryDirectory() as value:
            root=fixture(Path(value));(root/'public/feeds/reports.json').write_text('tampered');self.assertNotEqual(self.run_verify(root).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=fixture(Path(value));(root/'public/extra').write_text('x');self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_public_symlink_hardlink_and_fifo_fail_without_hanging(self):
        for mode in ('symlink','hardlink','fifo'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as value:
                root=fixture(Path(value));target=root/'public/hostile'
                if mode=='symlink':target.symlink_to(root/'public/feeds/reports.json')
                elif mode=='hardlink':target.hardlink_to(root/'public/feeds/reports.json')
                else:target.parent.mkdir(parents=True,exist_ok=True);__import__('os').mkfifo(target)
                result=self.run_verify(root);self.assertNotEqual(result.returncode,0)
    def test_checksum_consistent_rendered_html_tamper_fails_exact_binding(self):
        with tempfile.TemporaryDirectory() as value:
            root=fixture(Path(value));path=root/'public/reports/github/o/r'/HEAD/'r1/index.html';path.write_text(path.read_text().replace('</body>','<p>Unapproved claim</p></body>'));rebind_public(root);self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_history_contract_rejects_canonical_identity_revision_and_source_ambiguity(self):
        def pair(owner='o',repository='r',github_id=1,head=HEAD,revision=1,approved='2026-07-16T12:00:00Z',observation='a'*64,base='0'*40,archive='1'*64):
            item={'owner':owner,'repository':repository,'head_commit':head,'report_revision':revision,'observation_id':observation,'approval':{'id':hashlib.sha256(f'{owner}:{repository}:{head}:{revision}:{approved}'.encode()).hexdigest(),'approved_by':'reviewer','approved_at':approved}}
            record={'repository':{'owner':owner,'name':repository,'github_id':github_id,'license_spdx':'MIT'},'source':{'base_commit':base,'head_commit':head,'source_archive_sha256':archive},'publication':{'report_revision':revision}}
            return item,record
        valid=(pair(),pair(head='c'*40,approved='2026-07-16T13:00:00Z',observation='e'*64))
        release_verifier.validate_history(valid);release_verifier.validate_history((pair(),pair(revision=2,approved='2026-07-16T13:00:00Z')))
        invalid=((pair(),pair(owner='O')), (pair(),pair(owner='x')), (pair(),pair(owner='O',repository='R',github_id=2)), (pair(),pair(revision=3,approved='2026-07-16T13:00:00Z')), (pair(),pair(revision=2,approved='2026-07-16T11:00:00Z')), (pair(),pair(revision=2,approved='2026-07-16T13:00:00Z',observation='e'*64)), (pair(),pair(revision=2,approved='2026-07-16T13:00:00Z',archive='f'*64)))
        for pairs in invalid:
            with self.subTest(pairs=pairs),self.assertRaises(release_verifier.VerificationError):release_verifier.validate_history(pairs)
    def test_checksum_consistent_feed_latest_and_badge_semantic_tamper_fail(self):
        mutations=(('feeds/reports.json',canonical({'schema_version':'1.0','reports':[]})),('reports/github/o/r/latest.json',canonical({'publication_status':'UNAVAILABLE'})),('badges/o/r.svg',badge('Certified secure')))
        for relative,data in mutations:
            with self.subTest(relative=relative),tempfile.TemporaryDirectory() as value:
                root=fixture(Path(value));(root/'public'/relative).write_bytes(data);rebind_public(root);self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_checksum_consistent_bundle_replacement_fails_content_binding(self):
        with tempfile.TemporaryDirectory() as value:
            root=fixture(Path(value));bundle_path=root/'public/reports/github/o/r'/HEAD/'r1/report.tar.gz';bundle_path.write_bytes(deterministic_tar({'checksums.txt':b'forged'}));request=json.loads((root/'operator/pr-request.json').read_text());request['publication_items'][0]['bundle_sha256']=digest(bundle_path.read_bytes());(root/'operator/pr-request.json').write_bytes(canonical(request));rebind_public(root);self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_retraction_target_chronology_reason_and_tombstone_privacy_fail_closed(self):
        mutations=(lambda record:record['target'].__setitem__('payload_sha256','f'*64),lambda record:record['approval'].__setitem__('approved_at','2026-07-16T14:00:00Z'),lambda record:record.__setitem__('reason_code','PUBLIC_ACCUSATION'))
        for mutate in mutations:
            with self.subTest(mutate=mutate),tempfile.TemporaryDirectory() as value:
                root=fixture(Path(value),True);rewrite_retraction(root,mutate);self.assertNotEqual(self.run_verify(root).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=fixture(Path(value),True);path=root/'public/reports/github/o/r'/HEAD/'r1/index.html';path.write_text(path.read_text()+' reviewer2 MAINTAINER_REQUEST');rebind_public(root);self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_repository_components_match_publisher_slug_contract(self):
        for value,valid in [('owner',True),('a.b-c_d',True),('.git',False),('-owner',False),('owner.',False),('a'*101,False),('Owner',True)]:
            with self.subTest(value=value):
                if valid:self.assertEqual(release_verifier.safe_component(value,'component'),value)
                else:
                    with self.assertRaises(release_verifier.VerificationError):release_verifier.safe_component(value,'component')
    def test_private_marker_registry_matches_publisher_public_boundary(self):
        for marker in (b'Basic dXNlcjpwYXNzd29yZA==',b'"raw_value":',b'"matched_text":',b'\x1b',b'access_token=supersecret'):
            with self.subTest(marker=marker):self.assertTrue(any(pattern.search(marker) for pattern in release_verifier.PRIVATE))
    def test_checksum_consistent_html_script_and_credential_fail(self):
        for marker in ('<script>alert(1)</script>','Authorization: Bearer real-secret-value'):
            with self.subTest(marker=marker),tempfile.TemporaryDirectory() as value:
                root=fixture(Path(value));path=root/'public/reports/github/o/r'/HEAD/'r1/index.html';path.write_text(path.read_text()+marker);rebind_public(root);self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_nested_malformed_record_returns_controlled_failure(self):
        with tempfile.TemporaryDirectory() as value:
            root=fixture(Path(value));records=root/'operator/approval-records';old=next(records.iterdir());record=json.loads(old.read_text());record['source']=[];old.unlink();raw=canonical(record);new_sha=digest(raw);(records/f'{new_sha}.json').write_bytes(raw);request=json.loads((root/'operator/pr-request.json').read_text());request['publication_items'][0]['approval_record_sha256']=new_sha;(root/'operator/pr-request.json').write_bytes(canonical(request));self.assertEqual(self.run_verify(root).returncode,2)
    def test_approval_record_absence_tamper_and_wrong_name_fail(self):
        for mode in ('absent','tamper','rename'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as value:
                root=fixture(Path(value));record=next((root/'operator/approval-records').iterdir())
                if mode=='absent':record.unlink()
                elif mode=='tamper':record.write_bytes(record.read_bytes()+b'x')
                else:record.rename(record.with_name('f'*64+'.json'))
                self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_retraction_record_and_neutral_tombstone_are_required(self):
        with tempfile.TemporaryDirectory() as value:
            root=fixture(Path(value),True);next((root/'operator/retraction-records').iterdir()).unlink();self.assertNotEqual(self.run_verify(root).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=fixture(Path(value),True);(root/'public/reports/github/o/r'/HEAD/'r1/report.json').write_text('leak');self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_unexpected_operator_entry_fails(self):
        with tempfile.TemporaryDirectory() as value:
            root=fixture(Path(value));(root/'operator/unbound.txt').write_text('x');self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_workflows_use_only_full_action_shas(self):
        text='\n'.join(p.read_text() for p in (ROOT/'.github/workflows').glob('*.yml'))
        for sha in SHAS.values():self.assertIn('@'+sha,text)
        for floating in ('@v3','@v4','@v5','@v7','@main','@master'):self.assertNotIn(floating,text)
    def test_pr_workflow_is_read_only_and_never_uses_pull_request_target(self):
        text=(ROOT/'.github/workflows/validate-publication.yml').read_text();self.assertIn('pull_request:',text);self.assertNotIn('pull_request_target',text);self.assertIn('contents: read',text);self.assertNotIn('id-token: write',text);self.assertNotIn('pages: write',text)
    def test_report_pr_changed_paths_are_restricted_to_public_and_operator(self):
        for paths,expected in [(('public/a','operator/pr-request.json'),0),(('.github/workflows/pwn.yml',),2),(('scripts/verify_release_repo.py',),2),(('src/engine.py',),2),(('../escape',),2),(( '/absolute',),2)]:
            with self.subTest(paths=paths),tempfile.TemporaryDirectory() as value:
                listing=Path(value)/'paths.txt';listing.write_text(''.join(path+'\n' for path in paths));result=subprocess.run([sys.executable,str(VERIFY_PATHS),str(listing)],capture_output=True,text=True);self.assertEqual(result.returncode,expected)
    def test_pr_workflow_uses_base_branch_verifier_against_separate_candidate_checkout(self):
        text=(ROOT/'.github/workflows/validate-publication.yml').read_text();self.assertGreaterEqual(text.count('actions/checkout@'),2);self.assertIn('ref: ${{ github.event.pull_request.base.sha }}',text);self.assertIn('path: trusted',text);self.assertIn('path: candidate',text);self.assertIn('python3 trusted/scripts/verify_changed_paths.py /tmp/changed-paths.txt',text);self.assertIn('python3 trusted/scripts/verify_release_repo.py --root candidate',text)
    def test_deploy_requires_main_protected_environment_and_attests_manifest(self):
        text=(ROOT/'.github/workflows/deploy-pages.yml').read_text();self.assertIn('branches: [main]',text);self.assertNotIn('workflow_dispatch',text);self.assertIn('environment:',text);self.assertIn('name: github-pages',text);self.assertIn('pages: write',text);self.assertIn('id-token: write',text);self.assertIn('attestations: write',text);self.assertIn('subject-path: public/SHA256SUMS.txt',text);self.assertLess(text.index('attest-build-provenance@'),text.index('deploy-pages@'))
    def test_deploy_permissions_are_job_scoped_least_privilege(self):
        text=(ROOT/'.github/workflows/deploy-pages.yml').read_text();before_jobs,verify_part=text.split('jobs:',1);verify_part,deploy_part=verify_part.split('\n  deploy:',1);self.assertNotIn('permissions:',before_jobs);self.assertIn('contents: read',verify_part);self.assertIn('attestations: write',verify_part);self.assertIn('id-token: write',verify_part);self.assertNotIn('pages: write',verify_part);self.assertIn('pages: write',deploy_part);self.assertIn('id-token: write',deploy_part);self.assertNotIn('attestations: write',deploy_part);self.assertNotIn('contents: read',deploy_part)
    def test_governance_matches_solo_maintainer_pr_and_ci_gates(self):
        policy=json.loads((ROOT/'governance/repository-policy.json').read_text())
        branch=policy['branch_protection'];submission=policy['report_submission'];pages=policy['pages_environment']
        self.assertEqual(policy['operating_mode'],'SOLO_MAINTAINER')
        self.assertTrue(branch['required_pull_request']);self.assertEqual(branch['required_approving_review_count'],0)
        self.assertFalse(branch['require_code_owner_reviews']);self.assertFalse(branch['require_last_push_approval'])
        self.assertEqual(branch['required_status_checks'],[{'context':'validate','app_id':15368}])
        self.assertTrue(branch['strict_status_checks']);self.assertTrue(branch['enforce_admins'])
        self.assertFalse(branch['allow_force_pushes']);self.assertFalse(branch['allow_deletions'])
        self.assertFalse(submission['direct_main_push']);self.assertFalse(submission['human_second_account_required'])
        self.assertTrue(submission['trusted_base_verifier_required'])
        self.assertEqual(pages['required_reviewers'],0);self.assertFalse(pages['prevent_self_review'])
        self.assertFalse(pages['can_admins_bypass']);self.assertTrue(pages['protected_branches_only'])
        self.assertIn('@9batalion',(ROOT/'.github/CODEOWNERS').read_text())

if __name__=='__main__':unittest.main()
