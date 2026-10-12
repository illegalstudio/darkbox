#!/usr/bin/env python3
"""Generate or check canonical catalogs without touching upstream documentation."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CATALOG = "docs/darkbox/bundle.json"


def render(version):
    base = ROOT / "archive" / version
    folders = set()
    files = []
    for path in sorted(base.rglob("*"), key=lambda p: p.relative_to(base).as_posix()):
        if path.is_symlink():
            raise ValueError(f"Symlinks are forbidden in the canonical bundle: {path}")
        relative = path.relative_to(base).as_posix()
        if path.is_dir():
            folders.add(relative)
        elif path.is_file() and relative != CATALOG:
            content = path.read_bytes()
            files.append({"path": relative, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    if not files:
        raise ValueError(f"Missing canonical source files for {version}")
    folders.update(["docs", "docs/darkbox"])
    data = {"darkbox": {"id": "darkbox", "version": version}, "folders": sorted(folders), "files": files}
    return (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--version", help="Limit the operation to one registered version")
    args = parser.parse_args()
    versions = json.loads((ROOT / "versions.json").read_text())["versions"]
    if args.version:
        versions = [row for row in versions if row["version"] == args.version]
        if not versions:
            raise ValueError(f"Unregistered version: {args.version}")
    for row in versions:
        version = row["version"]
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
            raise ValueError(f"Invalid version: {version}")
        path = ROOT / "archive" / version / CATALOG
        expected = render(version)
        actual = path.read_bytes() if path.exists() else None
        if actual != expected:
            if args.check or row["released"]:
                raise ValueError(f"Catalog differs from canonical sources for {version}; published bundles cannot be rewritten")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
        print(f"{version}: catalog matches canonical sources")
    source = ROOT / "schema" / "manifest.schema.json"
    latest = versions[-1]["version"]
    # The root schema is a convenience copy; versioned schemas are authoritative.
    if not args.version and source.read_bytes() != (ROOT / "schema" / latest / "manifest.schema.json").read_bytes():
        raise ValueError("The convenience manifest schema differs from the latest versioned schema")
    if not args.version and (ROOT / "schema/bundle.schema.json").read_bytes() != (ROOT / "schema" / latest / "bundle.schema.json").read_bytes():
        raise ValueError("The convenience catalog schema differs from the latest versioned schema")
    if not args.version and (ROOT / "docs/specification.md").read_bytes() != (ROOT / "specification" / f"{latest}.md").read_bytes():
        raise ValueError("The convenience specification differs from the latest versioned specification")
    archive_versions = {p.name for p in (ROOT / "archive").iterdir() if p.is_dir()}
    registered = {row["version"] for row in json.loads((ROOT / "versions.json").read_text())["versions"]}
    if archive_versions != registered:
        raise ValueError("Every canonical archive version must have a registry entry")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
