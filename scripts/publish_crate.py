#!/usr/bin/env python3
"""Publish the checked crate, preserving immutable existing registry versions."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def remote_version(name, version):
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}/{version}",
        headers={"User-Agent": "darkbox-release (https://github.com/illegalstudio/darkbox)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)["version"]
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def matches(remote, checksum):
    if remote.get("yanked") or remote.get("checksum") != checksum:
        raise ValueError("Existing crates.io version is yanked or differs from the checked crate; refusing publication")


def publish():
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    name, version = package["name"], package["version"]
    if name != "darkbox":
        raise ValueError("Unexpected crate name")
    archive = ROOT / "target/package" / f"{name}-{version}.crate"
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    existing = remote_version(name, version)
    if existing is not None:
        matches(existing, checksum)
        print(f"{name} {version} is already published with the identical checksum")
        return
    if not os.environ.get("CARGO_REGISTRY_TOKEN"):
        raise ValueError("Missing CARGO_REGISTRY_TOKEN repository secret")
    subprocess.run(["cargo", "+stable", "publish", "--locked", "--registry", "crates-io"], cwd=ROOT, check=True)
    for attempt in range(12):
        published = remote_version(name, version)
        if published is not None:
            matches(published, checksum)
            print(f"Verified crates.io publication: {name} {version}")
            return
        if attempt < 11:
            time.sleep(5)
    raise ValueError("Upload completed but registry confirmation timed out; retry this exact tag")


if __name__ == "__main__":
    try:
        publish()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
