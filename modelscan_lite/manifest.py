"""SHA-256 manifest: pin model artifacts so later tampering (or a swapped download) gets caught."""
import hashlib
import json
from pathlib import Path


def sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def build(root: Path, files) -> dict:
    return {str(p.relative_to(root)).replace("\\", "/"): sha256(p) for p in files}


def verify(root: Path, manifest_path: Path) -> list[str]:
    """Return a list of problems. An empty list means the artifacts match the manifest exactly."""
    expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems = []
    for rel, digest in expected.items():
        p = root / rel
        if not p.exists():
            problems.append(f"missing: {rel}")
        elif sha256(p) != digest:
            problems.append(f"modified: {rel}")
    return problems
