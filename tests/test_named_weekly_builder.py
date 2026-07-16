from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
from test_release_repo import canonical,fixture  # noqa:E402
from test_named_weekly_reviews import add_weekly,weekly_report  # noqa:E402
BUILD=ROOT/'scripts/build_named_weekly.py'
IMMUTABLE=ROOT/'scripts/verify_weekly_immutability.py'
METADATA=ROOT/'scripts/verify_weekly_pr_metadata.py'
VERIFY=ROOT/'scripts/verify_release_repo.py'

PRIVATE_SCHEMA='coderisktools.observatory.private-weekly-trial.v1'
def private_trial(repository,**changes):
    value={'schema':PRIVATE_SCHEMA,'repository':repository,'stars':50_000,'license_spdx':'MIT','status':'COMPLETE','scanner_version':'3.0.0','firewall_version':'4.3.0','worker_network':'NONE','target_code_executed':False};value.update(changes);return value

def write_inputs(root:Path,values):
    root.mkdir(mode=0o700);root.chmod(0o700);paths=[]
    for index,value in enumerate(values):
        path=root/f'{index}.json';path.write_bytes(canonical(value));path.chmod(0o600);paths.append(path)
    return paths

def initialize_git(root:Path):
    subprocess.run(['git','-C',str(root),'init','-b','main'],check=True,capture_output=True);subprocess.run(['git','-C',str(root),'config','user.name','Weekly Test'],check=True);subprocess.run(['git','-C',str(root),'config','user.email','weekly@example.invalid'],check=True);subprocess.run(['git','-C',str(root),'add','.'],check=True);subprocess.run(['git','-C',str(root),'commit','-m','fixture'],check=True,capture_output=True);return root

def git_source(path:Path,weekly=False):return initialize_git(add_weekly(fixture(path)) if weekly else fixture(path))

def run_builder(source,output,inputs,week='2026-W30'):
    command=[sys.executable,str(BUILD),'--source-root',str(source),'--output-root',str(output),'--week',week]
    for path in inputs:command.extend(('--private-input',str(path)))
    return subprocess.run(command,capture_output=True,text=True)

class NamedWeeklyBuilderTests(unittest.TestCase):
    def test_builder_is_transactional_verified_and_publishes_only_approved_project_fields(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source');identities=['alpha/one','beta/two','gamma/three'];inputs=write_inputs(root/'private',[private_trial(identity) for identity in identities]);output=root/'candidate'
            result=run_builder(source,output,inputs);self.assertEqual(result.returncode,0,result.stderr);self.assertFalse((source/'public/weekly').exists());self.assertFalse((output/'.git').exists())
            verified=subprocess.run([sys.executable,str(VERIFY),'--root',str(output)],capture_output=True,text=True);self.assertEqual(verified.returncode,0,verified.stderr)
            weekly=b''.join(path.read_bytes().lower() for path in (output/'public/weekly').rglob('*') if path.is_file())
            for identity in identities:self.assertIn(identity.encode(),weekly)
            report=json.loads((output/'public/weekly/2026-W30/report.json').read_text());self.assertEqual([project['name'] for project in report['projects']],identities);self.assertNotIn('stars',weekly.decode());self.assertNotIn('finding_count',weekly.decode());self.assertNotIn('critical',weekly.decode())
            request=json.loads((output/'operator/pr-request.json').read_text());self.assertEqual(request['schema'],'coderisktools.observatory.pr-request.v4');self.assertEqual(len(request['weekly_reports']),1)
    def test_builder_rejects_small_duplicate_or_ineligible_cohorts_without_output(self):
        variants=(
            [private_trial('a/one'),private_trial('b/two')],
            [private_trial('a/one'),private_trial('b/two'),private_trial('c/three'),private_trial('d/four')],
            [private_trial('a/one'),private_trial('A/ONE'),private_trial('c/three')],
            [private_trial('a/one'),private_trial('b/two'),private_trial('c/three',worker_network='USED')],
            [private_trial('a/one'),private_trial('b/two'),private_trial('c/three',stars=9_999)],
        )
        for index,values in enumerate(variants):
            with self.subTest(index=index),tempfile.TemporaryDirectory() as value:
                root=Path(value);source=git_source(root/'source');inputs=write_inputs(root/'private',values);output=root/'candidate';self.assertNotEqual(run_builder(source,output,inputs).returncode,0);self.assertFalse(output.exists())
    def test_builder_rejects_existing_week(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source',weekly=True);inputs=write_inputs(root/'private',[private_trial('a/one'),private_trial('b/two'),private_trial('c/three')]);output=root/'candidate';self.assertNotEqual(run_builder(source,output,inputs).returncode,0);self.assertFalse(output.exists())
    def test_builder_rejects_private_inputs_inside_source_repository(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source');inputs=write_inputs(source/'private',[private_trial('a/one'),private_trial('b/two'),private_trial('c/three')]);output=root/'candidate';self.assertNotEqual(run_builder(source,output,inputs).returncode,0);self.assertFalse(output.exists())
    def test_multiple_weeks_are_sorted_and_latest_is_newest(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source');inputs=write_inputs(root/'private',[private_trial('a/one'),private_trial('b/two'),private_trial('c/three')]);first=root/'first';second=root/'second'
            self.assertEqual(run_builder(source,first,inputs,'2026-W30').returncode,0);initialize_git(first);self.assertEqual(run_builder(first,second,inputs,'2026-W31').returncode,0)
            latest=json.loads((second/'public/weekly/latest.json').read_text());index=json.loads((second/'public/weekly/index.json').read_text());self.assertEqual(latest['week'],'2026-W31');self.assertEqual([entry['week'] for entry in index['reports']],['2026-W31','2026-W30'])
            request=json.loads((second/'operator/pr-request.json').read_text());request['weekly_reports'].reverse();(second/'operator/pr-request.json').write_bytes(canonical(request));self.assertNotEqual(subprocess.run([sys.executable,str(VERIFY),'--root',str(second)],capture_output=True,text=True).returncode,0)

    def test_builder_rejects_hostile_private_inputs_tracked_symlink_and_nested_output(self):
        import os
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source');private=root/'private';inputs=write_inputs(private,[private_trial('a/one'),private_trial('b/two'),private_trial('c/three')]);alias=root/'alias.json';os.link(inputs[0],alias);inputs[0]=alias;self.assertNotEqual(run_builder(source,root/'out',inputs).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source');private=root/'private';inputs=write_inputs(private,[private_trial('a/one'),private_trial('b/two')]);fifo=root/'trial.fifo';os.mkfifo(fifo);inputs.append(fifo);self.assertNotEqual(run_builder(source,root/'out',inputs).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source');(source/'tracked-link').symlink_to('README.md');subprocess.run(['git','-C',str(source),'add','tracked-link'],check=True);subprocess.run(['git','-C',str(source),'commit','-m','link'],check=True,capture_output=True);inputs=write_inputs(root/'private',[private_trial('a/one'),private_trial('b/two'),private_trial('c/three')]);self.assertNotEqual(run_builder(source,root/'out',inputs).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source');inputs=write_inputs(root/'private',[private_trial('a/one'),private_trial('b/two'),private_trial('c/three')]);self.assertNotEqual(run_builder(source,source/'nested-output',inputs).returncode,0)
    def test_builder_rejects_world_readable_private_file_or_parent(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source');inputs=write_inputs(root/'private',[private_trial('a/one'),private_trial('b/two'),private_trial('c/three')]);inputs[0].chmod(0o644);self.assertNotEqual(run_builder(source,root/'out',inputs).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);source=git_source(root/'source');inputs=write_inputs(root/'private',[private_trial('a/one'),private_trial('b/two'),private_trial('c/three')]);inputs[0].parent.chmod(0o755);self.assertNotEqual(run_builder(source,root/'out',inputs).returncode,0)

class WeeklyImmutabilityTests(unittest.TestCase):
    def run_gate(self,base,candidate,paths):
        listing=base.parent/'paths.txt';listing.write_text(''.join(path+'\n' for path in paths));return subprocess.run([sys.executable,str(IMMUTABLE),'--base',str(base),'--candidate',str(candidate),'--paths',str(listing)],capture_output=True,text=True)
    def test_one_new_bound_week_passes(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);base=fixture(root/'base');candidate=add_weekly(fixture(root/'candidate'));paths=['public/weekly/2026-W30/report.json','public/weekly/2026-W30/index.html','public/weekly/index.json','public/weekly/latest.json','public/SHA256SUMS.txt','operator/pr-request.json'];self.assertEqual(self.run_gate(base,candidate,paths).returncode,0)
    def test_existing_week_mutation_or_incomplete_week_fails(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);base=add_weekly(fixture(root/'base'));candidate=root/'candidate';shutil.copytree(base,candidate);path=candidate/'public/weekly/2026-W30/report.json';path.write_bytes(path.read_bytes()+b'x');self.assertNotEqual(self.run_gate(base,candidate,['public/weekly/2026-W30/report.json']).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);base=fixture(root/'base');candidate=add_weekly(fixture(root/'candidate'));self.assertNotEqual(self.run_gate(base,candidate,['public/weekly/2026-W30/report.json']).returncode,0)

    def test_backfill_mixed_payload_and_request_history_mutation_fail(self):
        paths=['public/weekly/2026-W29/report.json','public/weekly/2026-W29/index.html','public/weekly/index.json','public/weekly/latest.json','public/SHA256SUMS.txt','operator/pr-request.json']
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);base=add_weekly(fixture(root/'base'));candidate=add_weekly(fixture(root/'candidate'),weekly_report('2026-W29','2026-07-13','2026-07-19'));self.assertNotEqual(self.run_gate(base,candidate,paths).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);base=fixture(root/'base');candidate=add_weekly(fixture(root/'candidate'));mixed=['public/weekly/2026-W30/report.json','public/weekly/2026-W30/index.html','public/weekly/index.json','public/weekly/latest.json','public/SHA256SUMS.txt','operator/pr-request.json','public/reports/github/owner/repo/latest.json'];self.assertNotEqual(self.run_gate(base,candidate,mixed).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);base=fixture(root/'base');candidate=add_weekly(fixture(root/'candidate'));request=json.loads((candidate/'operator/pr-request.json').read_text());request['publication_items'][0]['owner']='private-owner';(candidate/'operator/pr-request.json').write_bytes(canonical(request));valid=['public/weekly/2026-W30/report.json','public/weekly/2026-W30/index.html','public/weekly/index.json','public/weekly/latest.json','public/SHA256SUMS.txt','operator/pr-request.json'];self.assertNotEqual(self.run_gate(base,candidate,valid).returncode,0)

    def test_weekly_immutability_gate_uses_trusted_base_script(self):
        text=(ROOT/'.github/workflows/validate-publication.yml').read_text()
        self.assertIn('python3 trusted/scripts/verify_weekly_immutability.py --base trusted --candidate candidate --paths /tmp/changed-paths.txt',text)
        self.assertNotIn('python3 candidate/scripts/verify_weekly_immutability.py',text)

    def test_controlled_security_pack_bootstrap_is_narrow_and_payload_preserving(self):
        policy=json.loads((ROOT/'governance/repository-policy.json').read_text());maintenance=policy['security_pack_maintenance'];self.assertEqual(maintenance['mode'],'CONTROLLED_ADMIN_BOOTSTRAP');self.assertEqual(maintenance['protected_payload_roots_unchanged'],['public','operator']);self.assertEqual(maintenance['temporary_control_change'],'REQUIRED_STATUS_CHECK_ONLY');self.assertTrue(maintenance['restore_strict_validate_immediately']);self.assertTrue(maintenance['synthetic_weekly_rehearsal_required_before_real_publication'])
        text=(ROOT/'docs/SECURITY_PACK_UPGRADE_V020.md').read_text();self.assertIn('Temporarily remove only the required status-check entry',text);self.assertIn('Immediately restore strict required check `validate`',text);self.assertIn('must not be reused for weekly report payloads',text)

class WeeklyMetadataTests(unittest.TestCase):
    PATHS=['public/weekly/2026-W30/report.json','public/weekly/2026-W30/index.html','public/weekly/index.json','public/weekly/latest.json','public/SHA256SUMS.txt','operator/pr-request.json']
    def candidate(self,root):
        import os
        repo=git_source(root/'repo');base=subprocess.run(['git','-C',str(repo),'rev-parse','HEAD'],check=True,capture_output=True,text=True).stdout.strip();subprocess.run(['git','-C',str(repo),'switch','-c','weekly/2026-W30'],check=True,capture_output=True)
        for value in self.PATHS:
            path=repo/value;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(value+'\n')
        subprocess.run(['git','-C',str(repo),'config','user.name','9batalion'],check=True);subprocess.run(['git','-C',str(repo),'config','user.email','38577463+9batalion@users.noreply.github.com'],check=True);subprocess.run(['git','-C',str(repo),'add','.'],check=True)
        env=os.environ.copy();env.update({'GIT_AUTHOR_DATE':'2026-07-20T08:00:00+00:00','GIT_COMMITTER_DATE':'2026-07-20T08:00:00+00:00'});subprocess.run(['git','-C',str(repo),'commit','-m','Named OSS weekly review 2026-W30'],check=True,capture_output=True,env=env)
        listing=root/'paths.txt';listing.write_text(''.join(value+'\n' for value in self.PATHS));return repo,base,listing
    def run_gate(self,repo,base,listing,**changes):
        import os
        env=os.environ.copy();env.update({'BASE_SHA':base,'PR_TITLE':'Named OSS weekly review 2026-W30','PR_BODY':'Publishes one verified named OSS review index. Technical findings and project-level security conclusions are not published.','HEAD_REF':'weekly/2026-W30','PR_AUTHOR':'9batalion','PR_DRAFT':'false','PR_LABELS':'[]','PR_ASSIGNEES':'[]','PR_REVIEWERS':'[]','PR_TEAMS':'[]','PR_MILESTONE':'null'});env.update(changes);return subprocess.run([sys.executable,str(METADATA),'--candidate',str(repo),'--paths',str(listing)],capture_output=True,text=True,env=env)
    def test_exact_metadata_passes_and_any_public_field_change_fails(self):
        with tempfile.TemporaryDirectory() as value:
            repo,base,listing=self.candidate(Path(value));self.assertEqual(self.run_gate(repo,base,listing).returncode,0)
            for changes in ({'PR_TITLE':'Repository alpha/one'},{'PR_BODY':'https://github.com/alpha/one'},{'HEAD_REF':'weekly/alpha-one'},{'PR_LABELS':'[{"name":"alpha-one"}]'},{'PR_MILESTONE':'{"title":"private-project"}'},{'PR_AUTHOR':'other-user'}):
                with self.subTest(changes=changes):self.assertNotEqual(self.run_gate(repo,base,listing,**changes).returncode,0)
    def test_commit_body_channel_fails(self):
        import os
        with tempfile.TemporaryDirectory() as value:
            repo,base,listing=self.candidate(Path(value));env=os.environ.copy();env.update({'GIT_AUTHOR_DATE':'2026-07-20T08:00:00+00:00','GIT_COMMITTER_DATE':'2026-07-20T08:00:00+00:00'});subprocess.run(['git','-C',str(repo),'commit','--amend','-m','Named OSS weekly review 2026-W30','-m','hidden metadata'],check=True,capture_output=True,env=env);self.assertNotEqual(self.run_gate(repo,base,listing).returncode,0)
    def test_raw_commit_headers_and_nonregular_git_mode_fail(self):
        import os
        with tempfile.TemporaryDirectory() as value:
            repo,base,listing=self.candidate(Path(value));raw=subprocess.run(['git','-C',str(repo),'cat-file','commit','HEAD'],check=True,capture_output=True).stdout;crafted=raw.replace(b'\n\n',b'\nencoding X-PRIVATE-ALPHA-ONE\n\n',1);object_id=subprocess.run(['git','-C',str(repo),'hash-object','-t','commit','-w','--stdin'],input=crafted,check=True,capture_output=True,text=False).stdout.decode().strip();subprocess.run(['git','-C',str(repo),'update-ref','HEAD',object_id],check=True);self.assertNotEqual(self.run_gate(repo,base,listing).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            repo,base,listing=self.candidate(Path(value));path=repo/self.PATHS[0];path.chmod(0o755);subprocess.run(['git','-C',str(repo),'add',self.PATHS[0]],check=True);env=os.environ.copy();env.update({'GIT_AUTHOR_DATE':'2026-07-20T08:00:00+00:00','GIT_COMMITTER_DATE':'2026-07-20T08:00:00+00:00'});subprocess.run(['git','-C',str(repo),'commit','--amend','--no-edit'],check=True,capture_output=True,env=env);self.assertNotEqual(self.run_gate(repo,base,listing).returncode,0)
    def test_workflow_uses_trusted_metadata_gate(self):
        text=(ROOT/'.github/workflows/validate-publication.yml').read_text();self.assertIn('ref: ${{ github.event.pull_request.head.sha }}',text);self.assertIn('fetch-depth: 0',text);self.assertIn('python3 trusted/scripts/verify_weekly_pr_metadata.py --candidate candidate --paths /tmp/changed-paths.txt',text);self.assertNotIn('python3 candidate/scripts/verify_weekly_pr_metadata.py',text);self.assertNotIn('Checkout candidate merge state',text)

if __name__=='__main__':unittest.main()
