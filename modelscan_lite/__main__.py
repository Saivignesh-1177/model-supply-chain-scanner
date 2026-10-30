"""CLI.

  python -m modelscan_lite scan  <file-or-dir> [--json]   exit 0 clean, 1 review/error, 2 malicious
  python -m modelscan_lite pin   <dir>                     write model.manifest.json
  python -m modelscan_lite verify <dir>                    check against model.manifest.json
"""
import argparse
import json
import sys
from pathlib import Path

from . import manifest
from .formats import iter_model_files, scan_file

EXIT = {"clean": 0, "review": 1, "error": 1, "malicious": 2}


def cmd_scan(target: str, as_json: bool) -> int:
    reports = [scan_file(p) for p in iter_model_files(target)]
    worst = max((EXIT[r.verdict] for r in reports), default=0)
    if as_json:
        print(json.dumps([{"path": r.path, "format": r.format, "verdict": r.verdict, "errors": r.errors,
                           "imports": [{"ref": i.ref, "severity": i.severity} for i in r.imports]}
                          for r in reports], indent=2))
        return worst
    for r in reports:
        print(f"[{r.verdict.upper():9}] {r.path} ({r.format})")
        for i in r.imports:
            if i.severity != "safe":
                print(f"    {i.severity:9} {i.ref}  @ byte {i.offset}")
        for e in r.errors:
            print(f"    error     {e}")
    print(f"\n{len(reports)} file(s) scanned")
    return worst


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="modelscan_lite", description="Static ML model supply-chain scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("target")
    s.add_argument("--json", action="store_true")
    for name in ("pin", "verify"):
        sub.add_parser(name).add_argument("dir")
    args = ap.parse_args(argv)

    if args.cmd == "scan":
        return cmd_scan(args.target, args.json)
    root = Path(args.dir)
    mpath = root / "model.manifest.json"
    if args.cmd == "pin":
        data = manifest.build(root, iter_model_files(root))
        mpath.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"pinned {len(data)} file(s) -> {mpath}")
        return 0
    problems = manifest.verify(root, mpath)
    for p in problems:
        print(p)
    print("OK" if not problems else f"{len(problems)} problem(s)")
    return 0 if not problems else 2


if __name__ == "__main__":
    sys.exit(main())
