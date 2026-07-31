#!/usr/bin/env python3
"""Normalize a vulnerability-looking ranking into the verified coverage contract.

The public contract is intentionally not a security ranking: popularity selects the
cohort, while scan_status only records execution completeness. No vulnerability
counts, scores, or security conclusions are published.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEEK = "2026-W30"
RANKING = ROOT / "public" / "rankings" / WEEK


def load_verifier():
    spec = importlib.util.spec_from_file_location("release_verifier", ROOT / "scripts" / "verify_release_repo.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load trusted renderer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    verifier = load_verifier()
    old = json.loads((RANKING / "report.json").read_text(encoding="utf-8"))
    entries = []
    for item in old["entries"]:
        complete = item.get("scan_status") == "complete" and item.get("scan_exit_code") == 0 and item.get("sha_match") is True
        entries.append({
            "rank": item["rank"],
            "repository": item["repository"],
            "repository_url": item["repository_url"],
            "head_sha": item["head_sha"],
            "stars": item["stars"],
            "license_spdx": item.get("license_spdx"),
            "scan_status": "complete" if complete else "partial",
            "publication_status": "NOT_PUBLISHED",
        })
    report = {
        "schema": "coderisktools.observatory.popularity-ranking.v1",
        "week": old["week"],
        "cohort": old["cohort"],
        "provenance": {
            "scanner_version": "3.1.1",
            "scanner_source_commit": "347511c70425b52b8ba794e0e68e659f23ced13f",
        },
        "publication": {
            "purpose": "POPULARITY_COHORT_SCAN_COVERAGE",
            "security_ranking": False,
            "raw_findings": "NOT_PUBLISHED",
            "firewall_results": "NOT_PUBLISHED",
        },
        "entries": entries,
        "limitations": list(verifier.RANKING_LIMITATIONS),
    }
    raw = verifier.canonical(report)
    rendered = verifier.render_ranking_html(report)
    (RANKING / "report.json").write_bytes(raw)
    (RANKING / "index.html").write_bytes(rendered)
    (RANKING / "checksums.txt").write_text(
        f"{hashlib.sha256(rendered).hexdigest()}  index.html\n"
        f"{hashlib.sha256(raw).hexdigest()}  report.json\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
