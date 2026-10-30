"""Static pickle analysis: list every import a pickle would perform, without unpickling.

Unpickling a file can call any importable function (that is what __reduce__ does), so loading an untrusted
model with torch.load / pickle.load / joblib.load amounts to remote code execution. We walk the opcode
stream with pickletools.genops, which only parses, and resolve GLOBAL / STACK_GLOBAL / INST targets.
"""
import pickletools
from dataclasses import dataclass

# Module -> None means everything in it is dangerous. A set lists only the dangerous names.
DANGEROUS: dict[str, set[str] | None] = {
    "os": None, "posix": None, "nt": None, "subprocess": None, "pty": None, "socket": None,
    "shutil": None, "runpy": None, "webbrowser": None, "ctypes": None, "importlib": None,
    "multiprocessing": None, "asyncio": None, "sys": None, "code": None, "commands": None,
    "requests": None, "urllib": None, "http": None, "smtplib": None, "ftplib": None,
    "pickle": {"loads", "load", "Unpickler"}, "_pickle": {"loads", "load", "Unpickler"},
    "marshal": {"loads", "load"}, "types": {"CodeType", "FunctionType"},
    "builtins": {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr",
                 "globals", "locals", "breakpoint", "input"},
    "__builtin__": {"eval", "exec", "compile", "open", "__import__", "getattr", "execfile", "file"},
    "operator": {"attrgetter", "methodcaller"}, "functools": {"partial"},
    "torch.serialization": {"load"}, "numpy.testing._private.utils": {"runstring"},
}

# Expected in normal ML checkpoints. Anything outside this list or DANGEROUS is "unknown" and goes to review.
SAFE_REFS = (
    "collections.OrderedDict", "torch._utils._rebuild_tensor", "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_parameter",
    "torch.FloatStorage", "torch.HalfStorage", "torch.BFloat16Storage", "torch.LongStorage",
    "torch.IntStorage", "torch.ByteStorage", "torch.BoolStorage", "torch.DoubleStorage",
    "torch.storage._load_from_bytes", "torch._tensor._rebuild_from_type_v2", "torch.Size",
    "torch.float", "torch.device", "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct",
    "numpy.ndarray", "numpy.dtype", "numpy.core.multiarray.scalar", "builtins.set", "builtins.frozenset",
    "builtins.slice", "builtins.complex", "builtins.bytearray", "_codecs.encode", "__builtin__.set",
)

STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING",
              "BINSTRING", "STRING"}


@dataclass(frozen=True)
class Import:
    module: str
    name: str
    severity: str  # "dangerous" | "unknown" | "safe"
    offset: int

    @property
    def ref(self) -> str:
        return f"{self.module}.{self.name}"


def classify(module: str, name: str) -> str:
    # Check dangerous first, and use exact or dotted-prefix matches only.
    # A bare startswith would let "builtins.setattr" pass as "builtins.set".
    root = module.split(".")[0]
    for mod in (module, root):
        if mod in DANGEROUS:
            names = DANGEROUS[mod]
            if names is None or name.split(".")[0] in names:
                return "dangerous"
    ref = f"{module}.{name}"
    if any(ref == p or ref.startswith(p + ".") for p in SAFE_REFS):
        return "safe"
    return "unknown"


def scan_pickle_bytes(data: bytes) -> list[Import]:
    """Return every import the pickle would perform.

    If the stream is malformed we raise ValueError. We never guess.
    """
    found: list[Import] = []
    strings: list[str] = []     # recent string pushes, used for STACK_GLOBAL
    memo: dict[int, str] = {}
    try:
        for op, arg, pos in pickletools.genops(data):
            name = op.name
            if name in STRING_OPS:
                strings.append(arg if isinstance(arg, str) else arg.decode("latin-1"))
            elif name in ("BINPUT", "LONG_BINPUT", "PUT") and strings:
                memo[int(arg)] = strings[-1]
            elif name == "MEMOIZE" and strings:
                memo[len(memo)] = strings[-1]
            elif name in ("BINGET", "LONG_BINGET", "GET") and int(arg) in memo:
                strings.append(memo[int(arg)])
            elif name in ("GLOBAL", "INST"):
                module, _, attr = arg.partition(" ")
                found.append(Import(module, attr, classify(module, attr), pos))
            elif name == "STACK_GLOBAL":
                if len(strings) < 2:
                    found.append(Import("?", "?", "unknown", pos))
                else:
                    module, attr = strings[-2], strings[-1]
                    found.append(Import(module, attr, classify(module, attr), pos))
    except Exception as exc:  # genops raises a mix of ValueError, KeyError, struct.error
        raise ValueError(f"malformed pickle stream: {exc}") from exc
    return found
