"""Container formats: raw pickle, PyTorch zip checkpoints, and safetensors."""
import json
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .pickle_scan import Import, scan_pickle_bytes

PICKLE_EXT = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib"}
MAX_SAFETENSORS_HEADER = 100 * 1024 * 1024


@dataclass
class FileReport:
    path: str
    format: str
    imports: list[Import] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.errors:
            return "error"
        sev = {i.severity for i in self.imports}
        if "dangerous" in sev:
            return "malicious"
        if "unknown" in sev:
            return "review"
        return "clean"


def scan_safetensors(path: Path) -> FileReport:
    """safetensors cannot execute code. We still validate the header so that a pickle renamed to
    .safetensors, or a header crafted to exhaust memory, gets caught."""
    rep = FileReport(str(path), "safetensors")
    size = path.stat().st_size
    with path.open("rb") as fh:
        raw = fh.read(8)
        if len(raw) < 8:
            rep.errors.append("truncated header")
            return rep
        (n,) = struct.unpack("<Q", raw)
        if n > MAX_SAFETENSORS_HEADER or n > size - 8:
            rep.errors.append(f"header length {n} exceeds file/limit")
            return rep
        try:
            header = json.loads(fh.read(n))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            rep.errors.append(f"invalid JSON header: {exc}")
            return rep
    data_len = size - 8 - n
    for name, meta in header.items():
        if name == "__metadata__":
            continue
        start, end = meta.get("data_offsets", [0, 0])
        if not (0 <= start <= end <= data_len):
            rep.errors.append(f"tensor {name!r} offsets out of bounds")
    return rep


def scan_file(path: str | Path) -> FileReport:
    path = Path(path)
    if path.suffix == ".safetensors":
        return scan_safetensors(path)
    if zipfile.is_zipfile(path):
        rep = FileReport(str(path), "zip/pytorch")
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.filename.endswith(".pkl"):
                    try:
                        rep.imports += scan_pickle_bytes(zf.read(info))
                    except ValueError as exc:
                        rep.errors.append(f"{info.filename}: {exc}")
        return rep
    rep = FileReport(str(path), "pickle")
    try:
        rep.imports = scan_pickle_bytes(path.read_bytes())
    except ValueError as exc:
        rep.errors.append(str(exc))
    return rep


def iter_model_files(root: str | Path):
    root = Path(root)
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and (p.suffix in PICKLE_EXT or p.suffix == ".safetensors"):
            yield p
