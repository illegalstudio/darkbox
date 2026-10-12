"""Publication guards must preserve old reference files and version support."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_guard", SOURCE / "scripts/check_releases.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class PublishedReferences(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="darkbox-release-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        original = GUARD.ROOT
        self.addCleanup(setattr, GUARD, "ROOT", original)
        GUARD.ROOT = self.root
        self.git("init", "-q")
        self.registry = {"versions": [{"version": "1.0.0", "released": True, "rules": "v1"}]}
        self.write("versions.json", json.dumps(self.registry))
        self.write("archive/1.0.0/README.md", "Published bytes\n")
        self.write("schema/1.0.0/manifest.schema.json", "{}\n")
        self.write("specification/1.0.0.md", "Published specification\n")
        self.write("tests/fixtures/1.0.0/example.json", "{}\n")
        self.git("add", ".")
        self.git("-c", "user.name=Darkbox Tests", "-c", "user.email=tests@example.invalid", "commit", "-qm", "Test baseline")

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def write(self, path, content):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content)

    def test_new_unpublished_version_is_allowed(self):
        self.registry["versions"].append({"version": "1.1.0", "released": False, "rules": "v1"})
        self.write("versions.json", json.dumps(self.registry))
        self.write("archive/1.1.0/README.md", "New bytes\n")
        GUARD.check("HEAD")

    def test_published_version_cannot_be_removed(self):
        self.write("versions.json", '{"versions": []}')
        with self.assertRaisesRegex(ValueError, "cannot lose support"):
            GUARD.check("HEAD")

    def test_publication_status_cannot_be_reversed(self):
        self.registry["versions"][0]["released"] = False
        self.write("versions.json", json.dumps(self.registry))
        with self.assertRaisesRegex(ValueError, "publication status"):
            GUARD.check("HEAD")

    def test_every_published_reference_category_is_immutable(self):
        for path in ("archive/1.0.0/README.md", "schema/1.0.0/manifest.schema.json", "specification/1.0.0.md", "tests/fixtures/1.0.0/example.json"):
            original = (self.root / path).read_text()
            self.write(path, "Changed\n")
            with self.assertRaisesRegex(ValueError, "changed"):
                GUARD.check("HEAD")
            self.write(path, original)


if __name__ == "__main__":
    unittest.main()
