# ML Model Supply-Chain Scanner (`modelscan_lite`)

![ci](https://github.com/Saivignesh-1177/model-supply-chain-scanner/actions/workflows/ci.yml/badge.svg)

**Problem:** `torch.load()`, `pickle.load()` and `joblib.load()` execute code. A model downloaded from a public
hub can carry a `__reduce__` payload that runs the moment someone loads it. This is OWASP **LLM03 Supply
Chain** and MITRE ATLAS **AML.T0010 ML Supply Chain Compromise**.

**What this tool does:** it statically scans model artifacts **without ever loading them**. It lists every
Python import the pickle would perform and classifies each one as `dangerous`, `unknown`, or `safe`. It also
validates safetensors headers and pins artifacts with a SHA-256 manifest.

Illustrative output:

```
$ python -m modelscan_lite scan ./downloads
[MALICIOUS] downloads/pytorch_model.bin (zip/pytorch)
    dangerous posix.system  @ byte 62
[CLEAN    ] downloads/model.safetensors (safetensors)
[REVIEW   ] downloads/head.pkl (pickle)
    unknown   mylib.layers.CustomHead  @ byte 2
```

## How it works

| Layer | Technique |
|---|---|
| Opcode walk | `pickletools.genops` parses the stream without executing it. GLOBAL, INST and STACK_GLOBAL imports are resolved, with memo (BINPUT/BINGET) tracking so protocol-4/5 indirection can't hide them. |
| Classification | A denylist covers `os`, `subprocess`, `builtins.eval/exec/getattr`, `socket`, `runpy`, `ctypes`, `marshal` and more. An allowlist covers ordinary PyTorch/NumPy rebuild functions. **Anything else is "unknown"** and goes to human review, so the default is to fail closed. |
| Containers | PyTorch zip checkpoints (each `*.pkl` member is scanned), raw pickles under any extension (`.bin`, `.ckpt`, `.joblib` …), and safetensors |
| safetensors | Validates header length (blocks memory-exhaustion headers), JSON, and tensor offset bounds, and catches pickles renamed to `.safetensors` |
| Integrity | `pin` / `verify` with a SHA-256 manifest detects swapped or tampered artifacts after review |
| Exit codes | `0` clean, `1` review/error, `2` malicious, so it can gate a CI/CD or MLOps pipeline |

## Usage

```bash
python -m modelscan_lite scan  path/to/model_or_dir [--json]
python -m modelscan_lite pin    models/      # after review
python -m modelscan_lite verify models/      # in deploy pipeline
python -m unittest -v
```

No dependencies. Tested on Python 3.10–3.12, with pickle protocols 0–5.

## Tests

Malicious fixtures are **generated at test time**, and the payload is `os.getcwd`, which is harmless. No
weaponized file is committed, and the tests never unpickle anything. Cases covered: every pickle protocol,
hand-assembled protocol-0 streams, prefix-confusion (`builtins.set` vs `builtins.setattr`, a bug the tests
caught during development), PyTorch zip archives, disguised extensions, malformed streams, safetensors header
bombs and out-of-bounds offsets, and manifest tampering.

## Limits

- A denylist can never be complete, which is why unknown imports fail closed to `review`.
- The scanner doesn't emulate the pickle VM, so a payload that builds an import name from string operations
  at runtime would show up as `?.?` (unknown) rather than being resolved.
- Prefer **safetensors** and set `torch.load(weights_only=True)`. This tool is for the artifacts where you can't.

## Next steps

- [ ] Keras `.h5` / `.keras` Lambda-layer detection
- [ ] ONNX custom-op and external-data path checks
- [ ] Sigstore / model-signing verification
