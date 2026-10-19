"""Unit tests for the experimental APKM static inventory helper."""
import importlib.util
import io
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("apkm-static-inventory.py")
spec = importlib.util.spec_from_file_location("apkm_static_inventory", SCRIPT)
assert spec and spec.loader
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def make_bundle(self, root: Path, members: list[tuple[str, bytes]]) -> Path:
        path = root / "sample.apkm"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in members:
                archive.writestr(name, content)
        return path

    @staticmethod
    def make_apk(*, native: bool = False) -> bytes:
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", b"minimal test manifest bytes")
            archive.writestr("classes.dex", b"test dex placeholder")
            if native:
                archive.writestr("lib/arm64-v8a/libsample.so", b"native placeholder")
        return payload.getvalue()

    def test_valid_base_and_split_are_inventoried_with_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.make_bundle(Path(directory), [
                ("base.apk", self.make_apk()),
                ("split_config.arm64_v8a.apk", self.make_apk(native=True)),
            ])
            report = inventory.analyze(bundle)
            self.assertEqual(report["zip_integrity"], "passed")
            self.assertEqual(len(report["split_apks"]), 2)
            self.assertEqual(report["split_apks"][0]["dex_files"], ["classes.dex"])
            self.assertIn("lib/arm64-v8a/libsample.so", report["split_apks"][1]["native_libraries"])
            self.assertEqual(report["base_apk_sha256"], report["split_apks"][0]["sha256"])

    def test_missing_base_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.make_bundle(Path(directory), [("metadata.json", b"{}")])
            with self.assertRaisesRegex(ValueError, "exactly one root-level base.apk"):
                inventory.analyze(bundle)

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.make_bundle(Path(directory), [("../base.apk", b"bad")])
            with self.assertRaisesRegex(ValueError, "unsafe member path"):
                inventory.analyze(bundle)

    def test_duplicate_outer_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.apkm"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("base.apk", b"first")
                    archive.writestr("base.apk", b"second")
            with self.assertRaisesRegex(ValueError, "duplicate member names"):
                inventory.analyze(path)

    def test_duplicate_embedded_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = io.BytesIO()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(apk, "w") as archive:
                    archive.writestr("AndroidManifest.xml", b"manifest")
                    archive.writestr("classes.dex", b"one")
                    archive.writestr("classes.dex", b"two")
            bundle = self.make_bundle(Path(directory), [("base.apk", apk.getvalue())])
            with self.assertRaisesRegex(ValueError, "duplicate member names"):
                inventory.analyze(bundle)

    def test_non_zip_base_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.make_bundle(Path(directory), [("base.apk", b"not a zip")])
            with self.assertRaisesRegex(ValueError, "not a valid ZIP"):
                inventory.analyze(bundle)


if __name__ == "__main__":
    unittest.main(verbosity=2)
