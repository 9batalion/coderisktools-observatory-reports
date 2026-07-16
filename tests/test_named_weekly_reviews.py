from __future__ import annotations

import copy
import html
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
from test_release_repo import canonical,digest,fixture,rebind_public  # noqa:E402
VERIFY=ROOT/'scripts/verify_release_repo.py'

LIMITATIONS=[
    'Project names identify public open-source repositories included in this weekly review index.',
    'Inclusion does not indicate a vulnerability, endorsement, certification, ranking, or accusation.',
    'Technical findings, paths, snippets, rules, secrets, and exact results are not published.',
    'Project names and links are used nominatively to identify the reviewed public repositories.',
]

def projects():
    return [
        {'name':'alpha/one','url':'https://github.com/alpha/one','license_spdx':'Apache-2.0','review_status':'REVIEW_COMPLETED'},
        {'name':'beta/two','url':'https://github.com/beta/two','license_spdx':'MIT','review_status':'REVIEW_COMPLETED'},
        {'name':'gamma/three','url':'https://github.com/gamma/three','license_spdx':'BSD-3-Clause','review_status':'REVIEW_COMPLETED'},
    ]

def weekly_report(week='2026-W30',start='2026-07-20',end='2026-07-26'):
    return {
        'schema':'coderisktools.observatory.named-weekly-review.v1',
        'week':week,
        'period':{'start':start,'end':end},
        'projects':projects(),
        'engines':{'scanner':'3.0.0','firewall':'4.3.0'},
        'isolation':{'worker_network':'NONE','target_code_executed':False},
        'publication':{'project_names':'PUBLISHED_FOR_EDITORIAL_INDEXING','technical_findings':'NOT_PUBLISHED','exact_results':'NOT_PUBLISHED','project_level_conclusion':'NONE'},
        'result':'NAMED_PROJECT_REVIEWS_COMPLETED_NO_PROJECT_LEVEL_SECURITY_CONCLUSION',
        'limitations':LIMITATIONS,
    }

def weekly_html(report):
    week=report['week'];scanner=report['engines']['scanner'];firewall=report['engines']['firewall'];names=[project['name'] for project in report['projects']];joined=', '.join(names);title=f'Open Source Security Review: {joined} — CodeRiskTools Weekly';description=f'CodeRiskTools weekly static review index for {joined}. No project-level vulnerability conclusion or technical findings are published.';project_items=''.join(f'<li><a href="{html.escape(project["url"],quote=True)}" rel="noopener noreferrer">{html.escape(project["name"])}</a> — SPDX {html.escape(project["license_spdx"])}, review completed</li>' for project in report['projects']);limitations=''.join(f'<li>{html.escape(item)}</li>' for item in report['limitations'])
    return f"<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'\"><meta name=\"description\" content=\"{html.escape(description,quote=True)}\"><title>{html.escape(title)}</title></head><body><h1>{html.escape(title)}</h1><p>Week: <code>{week}</code></p><p>CodeRiskTools completed a non-executing static review workflow for the named public open-source repositories below.</p><ul>{project_items}</ul><p>Engines: Secret Scanner {scanner}; AI Change Firewall {firewall}.</p><p>Isolation: worker network disabled; target code not executed.</p><p><strong>Inclusion does not mean that a vulnerability was found and is not a security certification or ranking.</strong></p><h2>Publication boundary</h2><p>Technical findings and exact project-level results are not published.</p><h2>Limitations</h2><ul>{limitations}</ul></body></html>".encode()

def add_weekly(root:Path,report=None):
    report=weekly_report() if report is None else report;week=report['week'];base=root/'public/weekly'/week;base.mkdir(parents=True,exist_ok=True)
    report_raw=canonical(report);html_raw=weekly_html(report);(base/'report.json').write_bytes(report_raw);(base/'index.html').write_bytes(html_raw)
    entry={'week':week,'report_path':f'/weekly/{week}/'}
    (root/'public/weekly/index.json').write_bytes(canonical({'schema':'coderisktools.observatory.named-weekly-index.v1','reports':[entry]}))
    (root/'public/weekly/latest.json').write_bytes(canonical(entry))
    request=json.loads((root/'operator/pr-request.json').read_text());request['schema']='coderisktools.observatory.pr-request.v4';request['branch']=f'weekly/{week}';request['weekly_reports']=[{'week':week,'report_sha256':digest(report_raw),'html_sha256':digest(html_raw)}];(root/'operator/pr-request.json').write_bytes(canonical(request));rebind_public(root);return root

class NamedWeeklyReviewTests(unittest.TestCase):
    def run_verify(self,root):return subprocess.run([sys.executable,str(VERIFY),'--root',str(root)],capture_output=True,text=True)
    def test_valid_closed_named_weekly_review_passes_with_seo_names(self):
        with tempfile.TemporaryDirectory() as value:
            root=add_weekly(fixture(Path(value)));result=self.run_verify(root);self.assertEqual(result.returncode,0,result.stderr);html_raw=(root/'public/weekly/2026-W30/index.html').read_text()
            for project in projects():
                self.assertIn(project['name'],html_raw);self.assertIn(project['url'],html_raw)
            self.assertIn('Open Source Security Review:',html_raw);self.assertIn('Inclusion does not mean that a vulnerability was found',html_raw)
    def test_week_period_project_engine_and_publication_tokens_are_closed(self):
        mutations=(
            lambda r:r.__setitem__('week','2026-W99'),
            lambda r:r['period'].__setitem__('end','2026-07-27'),
            lambda r:r['engines'].__setitem__('scanner','3.0.1'),
            lambda r:r['projects'][0].__setitem__('url','https://example.com/alpha/one'),
            lambda r:r['projects'][0].__setitem__('review_status','CRITICAL_FOUND'),
            lambda r:r['projects'][0].__setitem__('license_spdx','NONE'),
            lambda r:r['projects'].reverse(),
            lambda r:r['projects'].__setitem__(1,copy.deepcopy(r['projects'][0])),
            lambda r:r['projects'].append({'name':'delta/four','url':'https://github.com/delta/four','license_spdx':'MIT','review_status':'REVIEW_COMPLETED'}),
            lambda r:r['publication'].__setitem__('exact_results','PUBLISHED'),
            lambda r:r['publication'].__setitem__('project_level_conclusion','WEAK_SECURITY'),
            lambda r:r['isolation'].__setitem__('target_code_executed',0),
            lambda r:r.__setitem__('result','ALL_PROJECTS_SECURE'),
            lambda r:r['limitations'].__setitem__(0,'Critical vulnerabilities found.'),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate),tempfile.TemporaryDirectory() as value:
                report=weekly_report();mutate(report);self.assertNotEqual(self.run_verify(add_weekly(fixture(Path(value)),report)).returncode,0)
    def test_unknown_finding_fields_and_checksum_consistent_html_tamper_fail(self):
        for key,value in (('finding_count',3),('critical',True),('rule_ids',['SECRET_TOKEN'])):
            with self.subTest(key=key),tempfile.TemporaryDirectory() as temp:
                report=weekly_report();report['projects'][0][key]=value;self.assertNotEqual(self.run_verify(add_weekly(fixture(Path(temp)),report)).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=add_weekly(fixture(Path(value)));path=root/'public/weekly/2026-W30/index.html';path.write_bytes(path.read_bytes().replace(b'</body>',b'<!-- critical in alpha/one --></body>'));request=json.loads((root/'operator/pr-request.json').read_text());request['weekly_reports'][0]['html_sha256']=digest(path.read_bytes());(root/'operator/pr-request.json').write_bytes(canonical(request));rebind_public(root);self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_request_digest_index_and_latest_bindings_fail(self):
        with tempfile.TemporaryDirectory() as value:
            root=add_weekly(fixture(Path(value)));request=json.loads((root/'operator/pr-request.json').read_text());request['weekly_reports'][0]['report_sha256']='f'*64;(root/'operator/pr-request.json').write_bytes(canonical(request));self.assertNotEqual(self.run_verify(root).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=add_weekly(fixture(Path(value)));request=json.loads((root/'operator/pr-request.json').read_text());request['branch']='weekly/alpha-one';(root/'operator/pr-request.json').write_bytes(canonical(request));self.assertNotEqual(self.run_verify(root).returncode,0)
        for relative in ('weekly/index.json','weekly/latest.json'):
            with self.subTest(relative=relative),tempfile.TemporaryDirectory() as value:
                root=add_weekly(fixture(Path(value)));(root/'public'/relative).write_bytes(canonical({'tampered':True}));rebind_public(root);self.assertNotEqual(self.run_verify(root).returncode,0)
    def test_duplicate_week_request_and_unbound_week_directory_fail(self):
        with tempfile.TemporaryDirectory() as value:
            root=add_weekly(fixture(Path(value)));request=json.loads((root/'operator/pr-request.json').read_text());request['weekly_reports'].append(copy.deepcopy(request['weekly_reports'][0]));(root/'operator/pr-request.json').write_bytes(canonical(request));self.assertNotEqual(self.run_verify(root).returncode,0)
        with tempfile.TemporaryDirectory() as value:
            root=add_weekly(fixture(Path(value)));extra=root/'public/weekly/2026-W31';extra.mkdir();(extra/'report.json').write_bytes(canonical(weekly_report('2026-W31','2026-07-27','2026-08-02')));(extra/'index.html').write_bytes(b'x');rebind_public(root);self.assertNotEqual(self.run_verify(root).returncode,0)

if __name__=='__main__':unittest.main()
