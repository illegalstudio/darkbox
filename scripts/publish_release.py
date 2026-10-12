#!/usr/bin/env python3
"""Publish complete verified artifacts, keeping published releases immutable."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from release import VERSION, ROOT
from release_assets import checksums, pacman_checksums


def gh(*args):
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def existing_release(tag):
    result = subprocess.run(["gh", "api", f"repos/illegalstudio/darkbox/releases/tags/{tag}"],
                            capture_output=True, text=True)
    if result.returncode:
        if "(HTTP 404)" in result.stderr:
            # The tag endpoint only finds published releases. Authenticated
            # release listings also include drafts, including partial uploads.
            pages = json.loads(gh("api", "repos/illegalstudio/darkbox/releases?per_page=100",
                                  "--paginate", "--slurp"))
            matches = [release for page in pages for release in page if release["tag_name"] == tag]
            if len(matches) > 1:
                raise ValueError("Multiple releases use this tag; review them manually")
            return matches[0] if matches else None
        raise ValueError(f"Cannot query the release: {result.stderr.strip()}")
    return json.loads(result.stdout)


def publish(tag, commit, directory, pacman=False):
    if not re.fullmatch("v" + VERSION, tag) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Invalid tag or commit")
    version = tag[1:]
    digests = checksums(directory, version)
    expected_text = "".join(f"{digest}  {name}\n" for name, digest in digests.items())
    checksum_name = f"darkbox_{version}_checksums.txt"
    if (directory / checksum_name).read_text() != expected_text:
        raise ValueError("Combined checksums do not match the final packages")
    ref = json.loads(gh("api", f"repos/illegalstudio/darkbox/git/ref/tags/{tag}"))
    if ref["object"]["type"] != "tag":
        raise ValueError("The remote tag must be annotated")
    annotation = json.loads(gh("api", f"repos/illegalstudio/darkbox/git/tags/{ref['object']['sha']}"))
    if annotation["object"]["type"] != "commit" or annotation["object"]["sha"] != commit:
        raise ValueError("The remote release tag no longer points to the checked commit")
    checksum_names = [checksum_name]
    if pacman:
        arch = pacman_checksums(directory, version)
        name = f"darkbox_{version}_pacman_checksums.txt"
        if (directory / name).read_text() != "".join(f"{digest}  {asset}\n" for asset, digest in arch.items()):
            raise ValueError("Combined pacman checksums do not match the final packages")
        digests.update(arch)
        checksum_names.append(name)
    assets = sorted([*digests, *(name + ".sha256" for name in digests), *checksum_names])
    existing = existing_release(tag)
    if existing:
        if not existing["draft"]:
            raise ValueError("This release is already public and will not be overwritten. Retry only the Homebrew workflow if needed.")
        if existing["target_commitish"] != commit or existing["prerelease"]:
            raise ValueError("An existing draft does not match this release commit")
        if any(asset["name"] not in assets for asset in existing["assets"]):
            raise ValueError("The existing draft contains unexpected assets; review it manually")
    else:
        registry = json.loads((ROOT / "versions.json").read_bytes())["versions"]
        supported = ", ".join(row["version"] for row in registry if row["released"])
        notes = (f"Darkbox CLI {version}\n\n"
                 f"Published specification versions supported: {supported}. The CLI software version is independent of specification versions.\n\n"
                 "Packages: Linux x86-64, Linux ARM64 and macOS ARM64. SQLite and offline Darkbox references are included.\n\n"
                 + ("Native Arch Linux packages for x86_64 and aarch64 are also included. After enabling the Illegal Studio pacman repository, install with `sudo pacman -Syu darkbox`.\n\n" if pacman else "") +
                 "Install with `brew install illegalstudio/tap/darkbox` or `mise use -g github:illegalstudio/darkbox`. "
                 f"For a pinned mise installation use `mise use -g github:illegalstudio/darkbox@{version}`.\n\n"
                 f"Verify downloads against `darkbox_{version}_checksums.txt`. "
                 "The source archives retain the versioned specification, schemas and canonical documentation bundles.\n")
        with tempfile.TemporaryDirectory(prefix="darkbox-release-notes-") as temporary:
            path = Path(temporary) / "notes.md"
            path.write_text(notes)
            gh("release", "create", tag, "--repo", "illegalstudio/darkbox", "--draft", "--verify-tag",
               "--target", commit, "--title", f"Darkbox {version}", "--notes-file", str(path))
    gh("release", "upload", tag, "--repo", "illegalstudio/darkbox", "--clobber",
       *(str(directory / name) for name in assets))
    uploaded = existing_release(tag)
    if uploaded is None or {asset["name"] for asset in uploaded["assets"]} != set(assets):
        raise ValueError("The draft does not contain exactly the required release assets")
    sizes = {name: (directory / name).stat().st_size for name in assets}
    if any(asset["size"] != sizes[asset["name"]] for asset in uploaded["assets"]):
        raise ValueError("An uploaded asset has an unexpected size")
    for asset in uploaded["assets"]:
        digest = asset.get("digest")
        if digest and digest != "sha256:" + hashlib.sha256((directory / asset["name"]).read_bytes()).hexdigest():
            raise ValueError("An uploaded asset has an unexpected SHA-256 digest")
    gh("release", "edit", tag, "--repo", "illegalstudio/darkbox", "--draft=false", "--latest")
    print(f"Published https://github.com/illegalstudio/darkbox/releases/tag/{tag}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--pacman", action="store_true", help="Require and publish both Arch packages")
    args = parser.parse_args()
    publish(args.tag, args.commit, args.directory, args.pacman)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
