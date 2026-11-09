"""Registry publication must never replace or trust a different existing crate."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("publish_crate", Path(__file__).resolve().parents[1] / "scripts/publish_crate.py")
CRATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CRATE)


class CratePublication(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="darkbox-crate-tests-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "Cargo.toml").write_text('[package]\nname="darkbox"\nversion="1.4.0"\n')
        (root / "target/package").mkdir(parents=True)
        data = b"checked crate bytes"
        (root / "target/package/darkbox-1.4.0.crate").write_bytes(data)
        self.remote = {"checksum": hashlib.sha256(data).hexdigest(), "yanked": False}
        self.root_patch = patch.object(CRATE, "ROOT", root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_identical_retry_does_not_upload(self):
        with patch.object(CRATE, "remote_version", return_value=self.remote), patch.object(CRATE.subprocess, "run") as run:
            CRATE.publish()
            run.assert_not_called()

    def test_existing_conflicting_or_yanked_version_is_refused(self):
        for remote in [dict(self.remote, checksum="wrong"), dict(self.remote, yanked=True)]:
            with patch.object(CRATE, "remote_version", return_value=remote), patch.object(CRATE.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "refusing publication"):
                    CRATE.publish()
                run.assert_not_called()

    def test_new_publication_requires_secret(self):
        with patch.object(CRATE, "remote_version", return_value=None), patch.dict(os.environ, {}, clear=True), patch.object(CRATE.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "Missing CARGO_REGISTRY_TOKEN"):
                CRATE.publish()
            run.assert_not_called()

    def test_new_upload_is_confirmed_by_checksum(self):
        with patch.object(CRATE, "remote_version", side_effect=[None, None, self.remote]), patch.dict(os.environ, {"CARGO_REGISTRY_TOKEN": "test-only"}), patch.object(CRATE.subprocess, "run") as run, patch.object(CRATE.time, "sleep"):
            CRATE.publish()
            self.assertEqual(run.call_count, 1)

    def test_transport_failure_cannot_be_mistaken_for_an_absent_version(self):
        with patch.object(CRATE, "remote_version", side_effect=OSError("network")), patch.object(CRATE.subprocess, "run") as run:
            with self.assertRaises(OSError):
                CRATE.publish()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
