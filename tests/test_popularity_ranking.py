import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_verifier', ROOT / 'scripts' / 'verify_release_repo.py')
release_verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(release_verifier)


def ranking_entry(rank, name, sha, stars, scan_status='partial', publication_status='NOT_PUBLISHED'):
    return {
        'rank': rank,
        'repository': name,
        'repository_url': f'https://github.com/{name}',
        'head_sha': sha,
        'stars': stars,
        'license_spdx': 'MIT',
        'scan_status': scan_status,
        'publication_status': publication_status,
    }


def valid_ranking():
    names = [f'owner/repo-{index:02d}' for index in range(1, 16)]
    return {
        'schema': 'coderisktools.observatory.popularity-ranking.v1',
        'week': '2026-W30',
        'cohort': {
            'schema': 'coderisktools.public-popularity-cohort.v1',
            'metric': 'stargazers_count',
            'snapshot_at': '2026-07-21T14:12:07Z',
            'tie_break': 'repository lexicographic ascending',
            'size': 15,
        },
        'provenance': {
            'scanner_version': '3.0.1',
            'scanner_source_commit': '1c45de48edf1a36d3fda332ffa5e59da9fcd4631',
            'ruleset_digest': 'sha256:1d90a16900f6b3aff1f11ce31b05a8b72a4257049903063e284b8a1cdc69d6ee',
        },
        'publication': {
            'purpose': 'POPULARITY_COHORT_SCAN_COVERAGE',
            'security_ranking': False,
            'raw_findings': 'NOT_PUBLISHED',
            'firewall_results': 'NOT_PUBLISHED',
        },
        'entries': [ranking_entry(index, name, 'a' * 40, 1000 - index) for index, name in enumerate(names, 1)],
        'limitations': [
            'This is a popularity cohort and scan-coverage index, not a security ranking.',
            'Partial or failed scans are not interpreted as clean or vulnerable.',
            'Raw findings, paths, snippets, secrets, scores, grades, and firewall results are not published.',
        ],
    }


class RankingContractTests(unittest.TestCase):
    def test_valid_ranking_contract_passes(self):
        report = valid_ranking()
        self.assertEqual(release_verifier.validate_ranking_report(release_verifier.canonical(report), release_verifier.render_ranking_html(report)), report)

    def test_ranking_contract_rejects_wrong_sha_and_order_and_status(self):
        for mutate in (
            lambda report: report['entries'][0].__setitem__('head_sha', 'b' * 39),
            lambda report: report['entries'].__setitem__(0, report['entries'][1]),
            lambda report: report['entries'][0].__setitem__('publication_status', 'PUBLISH'),
        ):
            with self.subTest(mutate=mutate):
                report = valid_ranking()
                mutate(report)
                with self.assertRaises(release_verifier.VerificationError):
                    release_verifier.validate_ranking_report(release_verifier.canonical(report), b'<html>')


if __name__ == '__main__':
    unittest.main()
