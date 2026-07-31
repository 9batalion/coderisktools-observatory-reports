#!/usr/bin/env python3
"""Rebind the closed public manifest and ranking digests after artifact changes."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
OPERATOR = ROOT / "operator"

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def main() -> None:
    files = {}
    for path in sorted(PUBLIC.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            files[path.relative_to(PUBLIC).as_posix()] = sha(path.read_bytes())
    manifest = "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items()))
    (PUBLIC / "SHA256SUMS.txt").write_text(manifest, encoding="utf-8")

    request_path = OPERATOR / "pr-request.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    manifest_bytes = manifest.encode()
    request["public_tree_manifest_sha256"] = sha(manifest_bytes)
    request["public_tree_file_count"] = len(files)
    report = PUBLIC / "rankings" / "2026-W30" / "report.json"
    html = PUBLIC / "rankings" / "2026-W30" / "index.html"
    for binding in request.get("ranking_reports", []):
        if binding.get("week") == "2026-W30":
            binding["report_sha256"] = sha(report.read_bytes())
            binding["html_sha256"] = sha(html.read_bytes())
    request_path.write_bytes(canonical(request))

if __name__ == "__main__":
    main()
