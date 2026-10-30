"""Tests build their fixtures at runtime, and nothing in this file ever unpickles anything.

The "malicious" payloads reference os.getcwd, which is harmless even if loaded, but a real attacker would
swap in os.system. The scanner has to flag the os module either way.
"""
import collections
import io
import json
import os
import pickle
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from modelscan_lite import manifest
from modelscan_lite.formats import scan_file
from modelscan_lite.pickle_scan import classify, scan_pickle_bytes


class _Payload:
    def __reduce__(self):
        return (os.getcwd, ())


class _CustomLayer:
    pass


def refs(data: bytes) -> dict[str, str]:
    return {i.ref: i.severity for i in scan_pickle_bytes(data)}


class PickleOpcodes(unittest.TestCase):
    def test_all_protocols_flag_os(self):
        for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=proto):
                found = refs(pickle.dumps({"weights": [1, 2], "x": _Payload()}, protocol=proto))
                self.assertIn("dangerous", found.values(), found)
                self.assertTrue(any(r.startswith(("os.", "posix.", "nt.")) for r in found))

    def test_benign_state_dict_clean(self):
        state = collections.OrderedDict(layer1=[0.1, 0.2], bias=[0.0])
        found = refs(pickle.dumps(state, protocol=4))
        self.assertEqual(set(found.values()), {"safe"})

    def test_custom_class_needs_review(self):
        self.assertIn("unknown", refs(pickle.dumps(_CustomLayer(), protocol=2)).values())

    def test_handcrafted_global_opcode(self):
        # protocol-0 stream: c builtins\neval\n (S'1+1'\n tR.
        self.assertEqual(refs(b"cbuiltins\neval\n(S'1+1'\ntR."), {"builtins.eval": "dangerous"})

    def test_prefix_confusion(self):
        self.assertEqual(classify("builtins", "set"), "safe")
        self.assertEqual(classify("builtins", "setattr"), "dangerous")
        self.assertEqual(classify("subprocess", "Popen"), "dangerous")

    def test_malformed_stream_raises(self):
        with self.assertRaises(ValueError):
            scan_pickle_bytes(b"\x80\x04\x95garbage")


class Containers(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_pytorch_style_zip(self):
        p = self.tmp / "model.pt"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("archive/data.pkl", pickle.dumps(_Payload(), protocol=2))
            zf.writestr("archive/version", "3")
        self.assertEqual(scan_file(p).verdict, "malicious")

    def _safetensors(self, header: dict, data: bytes = b"\x00" * 8, lie: int | None = None) -> Path:
        h = json.dumps(header).encode()
        p = self.tmp / "m.safetensors"
        p.write_bytes(struct.pack("<Q", lie if lie is not None else len(h)) + h + data)
        return p

    def test_safetensors_valid(self):
        p = self._safetensors({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}})
        self.assertEqual(scan_file(p).verdict, "clean")

    def test_safetensors_oob_offsets(self):
        p = self._safetensors({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 4096]}})
        self.assertEqual(scan_file(p).verdict, "error")

    def test_safetensors_header_bomb(self):
        p = self._safetensors({}, lie=2 ** 40)
        self.assertEqual(scan_file(p).verdict, "error")

    def test_pickle_disguised_as_bin(self):
        p = self.tmp / "pytorch_model.bin"
        p.write_bytes(pickle.dumps(_Payload()))
        self.assertEqual(scan_file(p).verdict, "malicious")


class Manifest(unittest.TestCase):
    def test_tamper_detected(self):
        root = Path(tempfile.mkdtemp())
        f = root / "w.pkl"
        f.write_bytes(pickle.dumps([1, 2, 3]))
        (root / "model.manifest.json").write_text(json.dumps(manifest.build(root, [f])))
        self.assertEqual(manifest.verify(root, root / "model.manifest.json"), [])
        f.write_bytes(pickle.dumps([1, 2, 4]))
        self.assertEqual(manifest.verify(root, root / "model.manifest.json"), ["modified: w.pkl"])


if __name__ == "__main__":
    unittest.main()
