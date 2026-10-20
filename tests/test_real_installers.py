"""Checks for corpus tooling failure handling; uses no downloaded installers."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location(
    "real_installers", Path(__file__).resolve().parents[1] / "scripts/real-installers.py"
)
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)


class CorpusToolTests(unittest.TestCase):
    def test_nested_zip_member_is_verified_before_replacement(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(corpus, "ROOT", Path(temporary)):
            directory = Path(temporary) / "test-data/real-installers/sample"
            directory.mkdir(parents=True)
            payload = b"ISc(" + (0x01009500).to_bytes(4, "little")
            installer = directory / "installer.zip"
            with zipfile.ZipFile(installer, "w") as archive:
                archive.writestr("nested/data1.cab", payload)
                archive.writestr("../../unexpected", b"not a selected member")
            sample = {
                "id": "sample", "installer": {"path": "installer.zip", "sha256": corpus.digest(installer)},
                "inputs": [{"path": "data1.cab", "archive_path": "nested/data1.cab", "sha256": "0" * 64}],
                "preparation": {"kind": "zip"}, "version_file": "data1.cab",
                "raw_version": 0x01009500, "major_version": 9,
            }
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                corpus.fetch(sample)
            self.assertFalse((directory / "data1.cab").exists())
            sample["inputs"][0]["sha256"] = hashlib.sha256(payload).hexdigest()
            corpus.fetch(sample)
            self.assertEqual((directory / "data1.cab").read_bytes(), payload)
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ["data1.cab", "installer.zip"])
            # A corrupt existing input must fail rather than silently being accepted.
            (directory / "data1.cab").write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                corpus.fetch(sample)

    def test_comparison_keeps_valid_member_changes_and_invalid_indices(self):
        original = {"files": [{"index": 0, "valid": True, "sha256": "a"},
                              {"index": 1, "valid": False, "name_hex": "ff"}]}
        placeholder = {"files": [original["files"][0], {"index": 1, "valid": False, "name_hex": ""}]}
        self.assertEqual(corpus.comparable(original), corpus.comparable(placeholder))
        for changed in ({"index": 0, "valid": True, "sha256": "b"}, {"index": 0, "valid": False}):
            self.assertNotEqual(corpus.comparable(original), corpus.comparable({"files": [changed, original["files"][1]]}))
        self.assertNotEqual(corpus.comparable(original), corpus.comparable({"files": original["files"][:1]}))

    def test_c_replacement_cannot_record_expected_results(self):
        with patch("sys.argv", ["real-installers.py", "check-c", "sample", "--extractor", "unused", "--record-expected"]):
            with self.assertRaises(SystemExit) as error:
                corpus.main()
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
