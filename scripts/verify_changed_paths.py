#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path, PurePosixPath
import stat
import sys

ALLOWED={'public','operator'}

def main(argv=None)->int:
    args=sys.argv[1:] if argv is None else argv
    if len(args)!=1:
        print('usage: verify_changed_paths.py PATH_LIST',file=sys.stderr);return 2
    path=Path(args[0])
    try:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>1_000_000:raise ValueError('invalid path-list file')
        raw=path.read_bytes()
        if path.lstat().st_size!=len(raw):raise ValueError('path-list changed during read')
        lines=raw.decode('utf-8').splitlines()
        if not lines or len(lines)>10_000 or len(lines)!=len(set(lines)):raise ValueError('empty, duplicate, or excessive changed-path list')
        for value in lines:
            parts=PurePosixPath(value).parts
            if not value or value.startswith('/') or '\\' in value or any(part in {'','.','..'} for part in parts) or not parts or parts[0] not in ALLOWED:raise ValueError(f'forbidden report-PR path: {value}')
    except (OSError,UnicodeDecodeError,ValueError) as exc:
        print(f'CHANGED_PATHS_FAILED: {exc}',file=sys.stderr);return 2
    print(f'CHANGED_PATHS_OK: {len(lines)}');return 0

if __name__=='__main__':raise SystemExit(main())
