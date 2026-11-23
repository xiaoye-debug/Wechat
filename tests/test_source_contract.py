import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from verify_source_contract import bundle_filter, verify


class SourceContractTests(unittest.TestCase):
    def test_defaults_and_bundle_contract(self):
        result = verify()
        self.assertEqual(result["migrated_default_enabled"], 54)
        self.assertEqual(result["default_enabled_candidates"], 80)

    def test_loader_plist_encodings(self):
        ids = json.loads((ROOT / "tests/fixtures/hook-contract.json").read_text())["bundle_ids"]
        value = {"Filter": {"Bundles": ids}}
        encodings = {
            "binary": plistlib.dumps(value, fmt=plistlib.FMT_BINARY),
            "xml": plistlib.dumps(value, fmt=plistlib.FMT_XML),
            "openstep": ('{ Filter = { Bundles = (' + ','.join('"' + i + '"' for i in ids) + '); }; }').encode(),
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, content in encodings.items():
                with self.subTest(format=name):
                    path = Path(directory) / f"{name}.plist"
                    path.write_bytes(content)
                    self.assertEqual(bundle_filter(path), ids)

    def test_missing_filter_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.plist"
            path.write_text("{ Filter = {}; }")
            with self.assertRaises(AssertionError):
                bundle_filter(path)


if __name__ == "__main__":
    unittest.main()
