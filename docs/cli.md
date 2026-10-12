# Darkbox command-line tool

The Rust binary inspects and verifies project archives offline. It includes the manifest schemas, canonical catalogs and exact canonical file bytes for every specification version it supports. SQLite is bundled; no SQLite installation, network connection or original application is needed to run it.

## Installation and builds

Install a published binary with Homebrew or mise:

```sh
brew install illegalstudio/tap/darkbox
# Alternatively:
mise use -g github:illegalstudio/darkbox
```

The [repository installation guide](https://github.com/illegalstudio/darkbox#install) covers version pinning and direct GitHub downloads. Published binaries support Linux x86-64 and ARM64 with glibc 2.35 or later, and macOS ARM64 with macOS 11 or later. Software release numbers are independent of the embedded common specification versions. Packages preserve dependency notices and bundle SQLite.

Build from this repository with Rust 1.88 or later and a C compiler:

```sh
cargo install --path . --locked
darkbox --version
```

For a local executable without installing:

```sh
cargo build --release --locked
./target/release/darkbox versions
```

GitHub Actions also retains packages from successful CI runs. These are development builds, separate from published releases. All packages extract into a single `darkbox_<version>_<os>_<arch>/` directory containing the `darkbox` executable, instructions, licenses and dependency notices. Linux uses `.tar.gz`; macOS uses `.zip`. Release macOS binaries are signed and the final ZIP is notarized before publication. Ordinary CI packages are unsigned.

To create a package locally after building, install `rustup component add rust-docs` if the standard-library notices are absent, then use the matching platform label:

```sh
python3 scripts/package.py --target x86_64-unknown-linux-gnu
```

The output is written under `dist/`, with a SHA-256 checksum for the package. Each GitHub release also includes `darkbox_<version>_checksums.txt` listing all three packages. These checksums cover downloadable software packages; the canonical catalog inside a project covers only its static documentation. Checksums are not signatures. See [release maintenance](https://github.com/illegalstudio/darkbox/blob/main/docs/releases.md) for `make release` and workflow setup.

## Commands

```sh
darkbox verify example.project
darkbox inspect example.project
darkbox verify example.project --json
darkbox inspect example.project --json
darkbox versions
darkbox versions --json
```

The input filename extension is irrelevant. Both analysis commands leave the original untouched, validate safe ZIP structure and read every entry to check decompression, sizes and CRC. Database bytes are staged under generated names in one private temporary directory. SQLite opens those copies read-only, disables loadable extensions, distrusts database-supplied functions and removes the staging directory on completion or ordinary error return.

`verify` checks the exact supported common version, strict JSON, its schema, path and inventory rules, canonical documentation, profile-document presence and UTF-8 encoding, SQLite snapshot independence, logical table inventory, declared `userVersion`, `integrity_check` and `foreign_key_check`. The archive catalog is compared with the embedded official catalog; its hashes cannot authorize changed documentation. Unknown required extensions and unavailable SQLite capabilities are reported as unsupported.

Application profiles are not implemented by this binary. A successful result is **passed common machine checks**, with `application_validation = "not_performed"`. It does not certify the embedded profile's accuracy, SQL column semantics, application invariants, resource references or full project conformance. Use `verify --require-profile` when your workflow requires full profile validation: this binary returns unsupported instead of accepting common checks alone.

`inspect` reports the available manifest, ZIP entries and declared SQLite metadata. It does not certify conformance, enforce a version-specific manifest schema, compare canonical documentation or run SQLite integrity and foreign-key checks. Unknown common versions may still be inspected; unsafe paths, malformed JSON, broken ZIP data and applicable resource limits still prevent a successful inspection. Metadata can be partial when an error occurs.

`versions` lists the exact embedded specification versions and whether each has been published. A prepared version can be supported before publication. The CLI software version, specification versions, application data versions and optional creator-software version are independent, even when their numbers happen to match.

## Reports and exit codes

Human-readable output is the default. `--json` writes one JSON object to standard output, including on analysis failures. Usage errors and output-write failures are written to standard error. Applications should use JSON rather than parse display text.

JSON reports include `report_version`, `cli_version`, `command`, `file`, `status`, `scope`, `application_validation`, `supported_versions`, `manifest`, `entries`, `databases`, `checks`, `diagnostics` and effective `limits`. Entry records indicate whether their CRC was checked; database records indicate whether integrity and foreign keys were checked. `checks` identifies completed check groups, not application-profile certification. Diagnostics have a severity, stable code, optional archive path and explanatory message. Reports may acquire additional fields; consumers should ignore fields they do not use and explicitly support the report version.

| Exit code | Status | Meaning |
| --- | --- | --- |
| `0` | `passed` or `inspected` | Common checks passed, or inspection completed, respectively |
| `1` | `invalid` | Corrupt data or a violated checked common rule |
| `2` | No analysis report | Invalid command-line usage |
| `3` | `unsupported` | Unsupported specification, required extension, SQLite capability or requested profile validation |
| `4` | `resource_limit` | Processing stopped at a configured limit |
| `5` | `operational_error` | Input, staging or output I/O failure |

Multiple diagnoses can appear. Operational failure takes precedence over invalid data, then resource limits, then unsupported features. A failed report does not certify unchecked entries or databases; an inspection success is never a verification success.

## Resource limits

Both analysis commands accept these reader policies. Sizes are bytes, not decimal megabytes. Exceeding a limit is distinct from corruption; increase limits deliberately for larger legitimate files.

| Option | Default |
| --- | --- |
| `--max-archive-bytes` | `536870912` (512 MiB compressed input) |
| `--max-entry-bytes` | `268435456` (256 MiB uncompressed per entry) |
| `--max-total-bytes` | `1073741824` (1 GiB total uncompressed entries) |
| `--max-entries` | `10000` |
| `--max-metadata-bytes` | `4194304` (4 MiB per manifest or captured text/reference file) |
| `--timeout-seconds` | `60` for the entire analysis |

ZIP counts are bounded before constructing the ZIP library's index. Advertised sizes and actual streamed bytes are checked separately. JSON nesting is limited to 128 levels; numeric literals are limited to 4096 bytes and exponent magnitude 4096 before schema arithmetic. SQLite also limits SQL size, value size and expression depth, uses a small page cache and an interrupt handler tied to the analysis deadline. The deadline is checked cooperatively while parsing, streaming and executing SQLite operations; it is not an operating-system process quota. Temporary disk use remains bounded by the configured uncompressed limits. Abrupt termination such as a killed process can leave temporary files for the operating system to clean up.

## Maintaining version support

`versions.json` registers each supported specification version, its publication state and implemented rule set. `archive/<version>/` holds its exact canonical bundle; `specification/<version>.md`, the schemas in `schema/<version>/` and `tests/fixtures/<version>/` retain its rules, schemas and example projects. `docs/specification.md` and the root schemas are convenience copies for the current version. Build-time checks refuse omitted archive versions, inconsistent catalogs and unimplemented rule sets.

Every binary release must retain support for all specification versions published by that release date. Exact-version dispatch is mandatory; sharing a major number is not evidence of support. Future or unimplemented versions return unsupported. References are embedded at compile time and are never downloaded from an archive-provided URL.

For a new specification version, add its bundle, schema, fixtures and registry entry, implement any new rules, then regenerate its catalog while `released` is false:

```sh
python3 scripts/bundle_catalog.py --write --version 1.0.0
python3 scripts/bundle_catalog.py --check
python3 -m unittest discover -s tests -p 'test_*.py'
cargo test --all-targets --locked
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
```

The version in the regeneration command is an example; select the version being prepared. Publication sets its registry entry to `released: true` and freezes its canonical bundle, versioned schema, specification and fixtures. The release guard compares those files and retained support with a chosen Git baseline:

```sh
python3 scripts/check_releases.py --base HEAD
```

CI checks the pull request base or the preceding pushed revision. Release preparation and tagged CI also compare against the preceding software release tag, preserving every already-published specification version. New versions must pass the same registered-version fixture checks before publication. Updating the registry does not itself publish a release.
