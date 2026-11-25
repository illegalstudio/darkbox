#!/usr/bin/env python3
"""Ensure published references and supported versions survive later changes."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=False)


def check(base):
    previous = git("show", f"{base}:versions.json")
    if previous.returncode:
        # Earlier revisions predate the version registry.
        if git("rev-parse", "--verify", f"{base}^{{commit}}").returncode:
            raise ValueError(f"Unknown baseline revision: {base}")
        print("Baseline predates the version registry")
        return
    old = json.loads(previous.stdout)["versions"]
    current = {row["version"]: row for row in json.loads((ROOT / "versions.json").read_bytes())["versions"]}
    for row in old:
        if not row["released"]:
            continue
        version = row["version"]
        if version not in current or not current[version]["released"]:
            raise ValueError(f"Published version {version} cannot lose support or publication status")
        paths = [f"archive/{version}", f"schema/{version}", f"specification/{version}.md", f"tests/fixtures/{version}"]
        changes = git("diff", "--name-only", base, "--", *paths)
        if changes.returncode:
            raise ValueError("Cannot compare published references")
        if changes.stdout.strip():
            raise ValueError(f"Published references for {version} changed: {changes.stdout.decode().strip()}")
    extensions = {(row["namespace"], row["version"]): row
                  for row in json.loads((ROOT / "versions.json").read_bytes()).get("extensions", [])}
    for row in json.loads(previous.stdout).get("extensions", []):
        if not row["released"]:
            continue
        key = (row["namespace"], row["version"])
        if key not in extensions or not extensions[key]["released"]:
            raise ValueError(f"Published extension {key[0]} {key[1]} cannot lose support or publication status")
        if extensions[key]["minCommon"] != row["minCommon"]:
            raise ValueError(f"Published extension {key[0]} {key[1]} cannot change its minimum common version")
        changes = git("diff", "--name-only", base, "--", f"extensions/{key[0]}/{key[1]}")
        if changes.returncode:
            raise ValueError("Cannot compare published extension bundles")
        if changes.stdout.strip():
            raise ValueError(f"Published extension bundle {key[0]} {key[1]} changed: {changes.stdout.decode().strip()}")
    print("Published versions and references are retained")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="HEAD")
    args = parser.parse_args()
    check(args.base)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
