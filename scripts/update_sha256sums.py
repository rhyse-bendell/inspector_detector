from __future__ import annotations
import hashlib
from pathlib import Path

EXCLUDE_PARTS = {'.git', '.venv', '.build-venv', 'build', 'dist', '__pycache__'}
EXCLUDE_SUFFIXES = {'.pyc', '.wsb'}
OUT = Path('SHA256SUMS.txt')

def include(path: Path) -> bool:
    return not (set(path.parts) & EXCLUDE_PARTS) and path.suffix not in EXCLUDE_SUFFIXES and path != OUT

lines = []
for path in sorted(p for p in Path('.').rglob('*') if p.is_file() and include(p)):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {path.as_posix()}\n")
OUT.write_text(''.join(lines), encoding='utf-8')
