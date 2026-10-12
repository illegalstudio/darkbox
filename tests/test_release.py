"""Exercise release preparation and publication boundaries without remote writes."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE / "scripts"))
import package
import publish_release
import release
import release_assets


class VersionPolicy(unittest.TestCase):
    def test_first_version_and_next_patch_are_proposed(self):
        self.assertEqual(release.propose("1.0.0", None), "1.0.0")
        self.assertEqual(release.propose("1.0.0", "v1.0.0"), "1.0.1")
        self.assertEqual(release.propose("2.0.0", "v1.9.9"), "2.0.0")
        self.assertEqual(release.propose("1.0.0", "v1.10.0"), "1.10.1")

    def test_unstable_or_ambiguous_versions_are_rejected(self):
        for version in ("01.0.0", "v1.0.0", "1.0", "1.0.0-beta", "1.0.0+build", "1.0.0\n"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.version_tuple(version)

    def test_specification_publication_is_explicit(self):
        registry = {"versions": [{"version": "1.0.0", "released": True},
                                 {"version": "2.0.0", "released": False}]}
        release.publication_versions(registry, [])
        self.assertFalse(registry["versions"][1]["released"])
        release.publication_versions(registry, ["2.0.0"])
        self.assertTrue(registry["versions"][1]["released"])
        with self.assertRaises(ValueError):
            release.publication_versions(registry, ["3.0.0"])


class InteractiveRelease(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="darkbox-release-flow-")
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.root = base / "checkout"
        self.root.mkdir()
        self.origin = base / "origin.git"
        subprocess.run(["git", "init", "--bare", "--initial-branch=main", "-q", str(self.origin)], check=True)
        self.git("init", "--initial-branch=main", "-q")
        self.git("config", "user.name", "Darkbox Tests")
        self.git("config", "user.email", "tests@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")
        self.write("Cargo.toml", '[package]\nname = "darkbox"\nversion = "1.0.0"\nedition = "2024"\n\n[dependencies]\n')
        self.write("Cargo.lock", 'version = 4\n\n[[package]]\nname = "darkbox"\nversion = "1.0.0"\n\n[[package]]\nname = "dependency"\nversion = "9.9.9"\n')
        self.write("versions.json", json.dumps({"versions": [{"version": "1.0.0", "released": False, "rules": "v1"}]}))
        self.git("add", ".")
        self.git("commit", "-qm", "Initial fixture")
        self.git("remote", "add", "origin", str(self.origin))
        self.git("push", "-q", "origin", "main")
        self.original = {name: (self.root / name).read_bytes() for name in release.OWNED}
        self.addCleanup(patch.stopall)
        patch.object(release, "ROOT", self.root).start()
        self.real_run = release.run
        patch.object(release, "run", self.run_command).start()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def write(self, name, value):
        (self.root / name).write_text(value)

    def run_command(self, *args, **kwargs):
        if args[0] in ("make", sys.executable):
            return None
        return self.real_run(*args, **kwargs)

    def args(self, **overrides):
        return argparse.Namespace(**({"version": "1.0.1", "publish_spec": ["1.0.0"], "dry_run": False} | overrides))

    def assert_restored(self):
        for name, content in self.original.items():
            self.assertEqual((self.root / name).read_bytes(), content)
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertEqual(self.git("tag", "--list"), "")

    def test_dry_run_does_not_write_files_or_refs(self):
        release.release(self.args(dry_run=True))
        self.assert_restored()

    def test_cancellation_restores_versions_without_publishing(self):
        with patch("builtins.input", return_value="n"):
            release.release(self.args())
        self.assert_restored()

    def test_failed_checks_restore_preparation(self):
        def fail_check(*args, **kwargs):
            if args[0] == "make":
                raise subprocess.CalledProcessError(1, args)
            return self.run_command(*args, **kwargs)
        with patch.object(release, "run", fail_check), self.assertRaises(subprocess.CalledProcessError):
            release.release(self.args())
        self.assert_restored()

    def test_atomic_publication_prepares_only_release_metadata(self):
        with patch("builtins.input", return_value="y"):
            release.release(self.args())
        self.assertEqual(self.git("cat-file", "-t", "v1.0.1"), "tag")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertEqual(set(self.git("diff", "--name-only", "HEAD^", "HEAD").splitlines()), set(release.OWNED))
        self.assertEqual(release.software_version(), "1.0.1")
        self.assertIn('name = "dependency"\nversion = "9.9.9"', (self.root / "Cargo.lock").read_text())
        self.assertTrue(json.loads((self.root / "versions.json").read_bytes())["versions"][0]["released"])
        refs = self.git("ls-remote", "origin", "refs/heads/main", "refs/tags/v1.0.1^{}")
        self.assertEqual({line.split()[0] for line in refs.splitlines()}, {self.git("rev-parse", "HEAD")})
        release.check_tag("v1.0.1")

    def test_failed_push_retains_reviewable_commit_and_tag(self):
        def fail_push(*args, **kwargs):
            if args[:2] == ("git", "push"):
                raise subprocess.CalledProcessError(1, args)
            return self.run_command(*args, **kwargs)
        with patch.object(release, "run", fail_push), patch("builtins.input", return_value="y"), self.assertRaises(subprocess.CalledProcessError):
            release.release(self.args())
        self.assertEqual(self.git("cat-file", "-t", "v1.0.1"), "tag")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertEqual(self.git("ls-remote", "origin", "refs/tags/v1.0.1"), "")

    def test_dirty_checkout_is_rejected_before_changes(self):
        self.write("uncommitted.txt", "User changes\n")
        with self.assertRaisesRegex(ValueError, "dirty"):
            release.release(self.args())
        self.assertEqual((self.root / "uncommitted.txt").read_text(), "User changes\n")
        for name, content in self.original.items():
            self.assertEqual((self.root / name).read_bytes(), content)

    def test_mismatched_or_lightweight_release_tag_is_rejected(self):
        release.prepare("1.0.1", ["1.0.0"])
        self.git("add", ".")
        self.git("commit", "-qm", "Prepare fixture")
        self.git("tag", "v1.0.1")
        with self.assertRaisesRegex(ValueError, "annotated"):
            release.check_tag("v1.0.1")
        with self.assertRaisesRegex(ValueError, "differs"):
            release.check_tag("v1.0.2")


class FinalAssets(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="darkbox-release-assets-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in release_assets.asset_names("1.0.0"):
            binary = bytearray(32)
            if "_darwin_" in name:
                binary[:8] = bytes.fromhex("cffaedfe0c000001")
            else:
                binary[:6] = b"\x7fELF\x02\x01"
                binary[18:20] = (183 if "_arm64" in name else 62).to_bytes(2, "little")
            members = {"darkbox": bytes(binary), "LICENSE": b"MIT\n", "CLI.md": b"Commands\n", "Cargo.lock": b"Lock\n",
                       "THIRD_PARTY_NOTICES.md": b"Notices\n", "licenses/sqlite/copyright.html": b"Public domain\n",
                       "licenses/rust/COPYRIGHT-library.html": b"Rust notices\n"}
            content = package.archive_bytes(name.removesuffix(".tar.gz").removesuffix(".zip"), members, name.endswith(".zip"))
            (self.root / name).write_bytes(content)
            (self.root / (name + ".sha256")).write_text(f"{hashlib.sha256(content).hexdigest()}  {name}\n")

    def test_formula_uses_all_final_platform_digests(self):
        digests = release_assets.checksums(self.root, "1.0.0")
        formula = release_assets.formula("1.0.0", digests)
        self.assertIn("depends_on arch: :arm64", formula)
        self.assertIn('bin.install "darkbox"', formula)
        self.assertIn('pkgshare.install "LICENSE"', formula)
        for name, digest in digests.items():
            self.assertIn(f"/v1.0.0/{name}", formula)
            self.assertIn(digest, formula)

    def test_missing_platform_fails_before_formula_generation(self):
        (self.root / "darkbox_1.0.0_linux_arm64.tar.gz").unlink()
        with self.assertRaisesRegex(ValueError, "three packages"):
            release_assets.checksums(self.root, "1.0.0")

    def test_changed_final_package_is_rejected(self):
        (self.root / "darkbox_1.0.0_linux_amd64.tar.gz.sha256").write_text("0" * 64 + "  darkbox_1.0.0_linux_amd64.tar.gz\n")
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            release_assets.checksums(self.root, "1.0.0")

    def test_wrong_architecture_is_rejected(self):
        with self.assertRaises(ValueError):
            release_assets.check_binary(bytes.fromhex("cffaedfe07000001"), "darkbox_1.0.0_darwin_arm64.zip")
        with self.assertRaises(ValueError):
            release_assets.check_binary(b"\x7fELF\x02\x01" + b"\0" * 26, "darkbox_1.0.0_linux_amd64.tar.gz")

    def test_corrupt_combined_checksum_is_not_rewritten(self):
        path = self.root / "darkbox_1.0.0_checksums.txt"
        path.write_text("Corrupt\n")
        with patch.object(sys, "argv", ["release_assets.py", "--version", "1.0.0", "--directory", str(self.root)]), self.assertRaises(ValueError):
            release_assets.main()
        self.assertEqual(path.read_text(), "Corrupt\n")

    def test_public_release_is_never_overwritten(self):
        digests = release_assets.checksums(self.root, "1.0.0")
        (self.root / "darkbox_1.0.0_checksums.txt").write_text("".join(f"{digest}  {name}\n" for name, digest in digests.items()))
        commit = "a" * 40
        responses = [json.dumps({"object": {"type": "tag", "sha": "b" * 40}}),
                     json.dumps({"object": {"type": "commit", "sha": commit, "url": "https://example.invalid"}})]
        with patch.object(publish_release, "gh", side_effect=responses) as github, patch.object(publish_release, "existing_release", return_value={"draft": False}), self.assertRaisesRegex(ValueError, "already public"):
            publish_release.publish("v1.0.0", commit, self.root)
        self.assertEqual(github.call_count, 2)
        self.assertTrue(all(call.args[0] == "api" for call in github.call_args_list))

    def test_moved_remote_tag_prevents_release_writes(self):
        digests = release_assets.checksums(self.root, "1.0.0")
        (self.root / "darkbox_1.0.0_checksums.txt").write_text("".join(f"{digest}  {name}\n" for name, digest in digests.items()))
        responses = [json.dumps({"object": {"type": "tag", "sha": "b" * 40}}),
                     json.dumps({"object": {"type": "commit", "sha": "c" * 40}})]
        with patch.object(publish_release, "gh", side_effect=responses) as github, self.assertRaisesRegex(ValueError, "no longer points"):
            publish_release.publish("v1.0.0", "a" * 40, self.root)
        self.assertEqual(github.call_count, 2)

    def test_draft_becomes_public_only_after_all_assets_are_checked(self):
        digests = release_assets.checksums(self.root, "1.0.0")
        combined = f"darkbox_1.0.0_checksums.txt"
        (self.root / combined).write_text("".join(f"{digest}  {name}\n" for name, digest in digests.items()))
        files = [*digests, *(name + ".sha256" for name in digests), combined]
        commit = "a" * 40
        uploaded = {"draft": True, "assets": [
            {"name": name, "size": (self.root / name).stat().st_size,
             "digest": "sha256:" + hashlib.sha256((self.root / name).read_bytes()).hexdigest()}
            for name in files]}
        calls = []
        def github(*args):
            calls.append(args)
            if args[:2] == ("api", "repos/illegalstudio/darkbox/git/ref/tags/v1.0.0"):
                return json.dumps({"object": {"type": "tag", "sha": "b" * 40}})
            if args[0] == "api":
                return json.dumps({"object": {"type": "commit", "sha": commit}})
            return ""
        with patch.object(publish_release, "gh", github), patch.object(publish_release, "existing_release", side_effect=[None, uploaded]):
            publish_release.publish("v1.0.0", commit, self.root)
        commands = [call[:2] for call in calls if call[0] == "release"]
        self.assertEqual(commands, [("release", "create"), ("release", "upload"), ("release", "edit")])
        self.assertIn("--draft", next(call for call in calls if call[:2] == ("release", "create")))
        self.assertEqual(len(next(call for call in calls if call[:2] == ("release", "upload"))) - 6, 7)

    def test_incomplete_upload_stays_private(self):
        digests = release_assets.checksums(self.root, "1.0.0")
        (self.root / "darkbox_1.0.0_checksums.txt").write_text("".join(f"{digest}  {name}\n" for name, digest in digests.items()))
        responses = [json.dumps({"object": {"type": "tag", "sha": "b" * 40}}),
                     json.dumps({"object": {"type": "commit", "sha": "a" * 40}}), "", ""]
        with patch.object(publish_release, "gh", side_effect=responses) as github, patch.object(publish_release, "existing_release", side_effect=[None, {"assets": []}]), self.assertRaisesRegex(ValueError, "exactly"):
            publish_release.publish("v1.0.0", "a" * 40, self.root)
        self.assertFalse(any(call.args[:2] == ("release", "edit") for call in github.call_args_list))


if __name__ == "__main__":
    unittest.main()
