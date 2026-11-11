# Darkbox command-line tool

The Rust binary inspects, verifies and converts project ZIPs and quiescent directory packages offline. It includes the manifest schemas, canonical catalogs and exact canonical file bytes for every specification version it supports. SQLite is bundled; no SQLite installation, network connection or original application is needed to run it.

## Installation and builds

Install a published binary with Homebrew or mise:

```sh
brew install illegalstudio/tap/darkbox
# Alternatively:
mise use -g github:illegalstudio/darkbox
```

On Arch Linux, enable the [Illegal Studio pacman repository](https://github.com/illegalstudio/pacman#install), then install with `sudo pacman -Syu darkbox`. It serves x86_64 and aarch64 packages.

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

The output is written under `dist/`, with a SHA-256 checksum for the package. Each GitHub release also includes `darkbox_<version>_checksums.txt` listing the three portable packages and `darkbox_<version>_pacman_checksums.txt` listing the two native Arch packages. These checksums cover downloadable software packages; the canonical catalog inside a project covers only its static documentation. Checksums are not signatures. See [release maintenance](https://github.com/illegalstudio/darkbox/blob/main/docs/releases.md) for `make release` and workflow setup.

## Commands

```sh
darkbox verify example.project
darkbox inspect example.project
darkbox verify example.project --json
darkbox inspect example.project --json
darkbox versions
darkbox versions --json
darkbox verify protected.project --trust-store trust.json --require-protection
darkbox verify protected.project --trust-store trust.json --decryption-keys keys.json --json
```

The input filename extension is irrelevant. Both analysis commands leave the original untouched, validate safe ZIP structure and read every entry to check decompression, sizes and CRC. Database bytes are staged under generated names in one private temporary directory. SQLite opens those copies read-only, disables loadable extensions, distrusts database-supplied functions and removes the staging directory on completion or ordinary error return.

`verify` checks the exact supported common version, strict JSON, its schema, path and inventory rules, canonical documentation, profile-document presence and UTF-8 encoding, SQLite snapshot independence, logical table inventory, declared `userVersion`, `integrity_check` and `foreign_key_check`. The archive catalog is compared with the embedded official catalog; its hashes cannot authorize changed documentation. Unknown required extensions and unavailable SQLite capabilities are reported as unsupported.

For Darkbox 1.1.0, 1.2.0, 1.3.0, 1.4.0 and 1.5.0 it also recognizes the official `studio.illegal.darkbox.protection` extension version 1.0.0. It checks the complete SHA-256 inventory, detached Ed25519 signature against supplied trusted keys, protected file/BLOB structure, stable record identifiers and observed nonce uniqueness. Decryption keys additionally enable AES-256-GCM authentication against the package/file or database/table/column/record context. Plaintext semantics remain unchecked. See the complete [extension specification](../archive/1.1.0/docs/darkbox/protection/1.0.0.md) and [Rust API](library.md).

`--trust-store PATH` reads a JSON object mapping signer identifiers to 64 hexadecimal characters representing raw 32-byte Ed25519 public keys. `--decryption-keys PATH` reads an application-supplied private JSON object mapping key identifiers to 64 hexadecimal characters representing raw 32-byte AES keys. These files stay outside the package. No command accepts secret keys directly as command-line values, and reports never include supplied key bytes or decrypted plaintext. Key files are limited to 4 MiB. Malformed key configuration returns a usage error without echoing its contents. Inspect does not authenticate protection, even when these options are supplied.

`--require-protection` is an external expectation: verification fails if the official descriptor is absent. This detects removal of protection metadata when your workflow requires it. Without such an expectation an intentionally unprotected project cannot be distinguished from one whose entire protection descriptor was removed. An unknown signer returns unsupported and prevents ordinary opening/saving. With trusted signer keys but no decryption key, common and public protection checks can pass with encrypted contents explicitly reported as `key_absent`. Missing keys are not corruption. Wrong keys or substituted ciphertext/context yield `protection.authentication`; removed or invalid signatures yield separate signature diagnostics.

Application profiles are not implemented by this binary. A successful result is **passed common machine checks**, with `application_validation = "not_performed"`. It does not certify the embedded profile's accuracy, SQL column semantics, application invariants, resource references or full project conformance. Use `verify --require-profile` when your workflow requires full profile validation: this binary returns unsupported with `profile.unsupported` and `application_validation = "unsupported"` instead of accepting common checks alone. Integrating applications can register their own profile validators through the [Rust SDK](sdk.md).

`inspect` reports the available manifest, ZIP entries and declared SQLite metadata. It does not certify conformance, enforce a version-specific manifest schema, compare canonical documentation or run SQLite integrity and foreign-key checks. Unknown common versions may still be inspected; unsafe paths, malformed JSON, broken ZIP data and applicable resource limits still prevent a successful inspection. Metadata can be partial when an error occurs.

`versions` lists the exact embedded specification versions and whether each has been published. A prepared version can be supported before publication. The CLI software version, specification versions, application data versions and optional creator-software version are independent, even when their numbers happen to match.

## Reports and exit codes

Human-readable output is the default. `--json` writes one JSON object to standard output, including on analysis failures. Usage errors and output-write failures are written to standard error. Applications should use JSON rather than parse display text.

JSON report version 2 includes `report_version`, `cli_version`, `command`, `file`, `status`, `scope`, `application_validation`, `supported_versions`, `manifest`, `entries`, `trusted_resources`, `databases`, `protection`, `checks`, `diagnostics` and effective `limits`. Entry records indicate whether their CRC was checked; database records indicate whether integrity and foreign keys were checked. `protection` is null when protection was not checked; otherwise it reports the extension version, signature state, inventory result and every encrypted block with public context, block SHA-256, public `nonce_hex`, authentication state and `plaintext_validation = "not_performed"`. Authentication is `verified`, `key_absent`, `failed` or `not_verified`. A verified inventory with an unknown or invalid signature is not an authenticated inventory. `checks` identifies completed check groups, not application-profile certification. Diagnostics have a severity, stable code, optional archive path and explanatory message. Reports may acquire additional fields; consumers should ignore fields they do not use and explicitly support the report version.

Protection diagnostic codes include `protection.key_absent`, `protection.signer_unknown`, `protection.version`, `protection.block_version`, `protection.signature_missing`, `protection.signature_invalid`, `protection.authentication`, `protection.inventory`, `protection.nonce_reuse`, `protection.required` and `protection.missing`. Missing decryption keys are informational; trust and unsupported-version errors are unsupported; invalid signature, inventory and AEAD errors are invalid. Independent public and SQLite checks continue where structurally safe. Diagnostic inspection never claims cryptographic conformance.

| Exit code | Status | Meaning |
| --- | --- | --- |
| `0` | `passed` or `inspected` | Common checks passed, or inspection completed, respectively |
| `1` | `invalid` | Corrupt data or a violated checked common rule |
| `2` | No analysis report | Invalid command-line usage |
| `3` | `unsupported` | Unsupported specification, required extension, SQLite capability or requested profile validation |
| `4` | `resource_limit` | Processing stopped at a configured limit |
| `5` | `operational_error` | Input, staging or output I/O failure |
| `6` | `not_quiescent` | Active or interrupted directory; recover and seal in the owning application |

A not-quiescent diagnosis stops directory snapshot checks without certifying its data. Otherwise multiple diagnoses can appear. Operational failure takes precedence over invalid data, then resource limits, then unsupported features. A failed report does not certify unchecked entries or databases; an inspection success is never a verification success.

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

ZIP counts are bounded before constructing the ZIP library's index. Advertised sizes and actual streamed bytes are checked separately. JSON nesting is limited to 128 levels; numeric literals are limited to 4096 bytes and exponent magnitude 4096 before schema arithmetic. SQLite also limits SQL size, value size and expression depth, uses a small page cache and an interrupt handler tied to the analysis deadline. `max_entries` additionally bounds each protected table's row count and the total reported encrypted block count. For extension verification, regular files are staged under generated names in the same private directory, bounded by total uncompressed limits; plaintext from AEAD verification stays in memory. The deadline is checked cooperatively while parsing, streaming and executing SQLite operations; it is not an operating-system process quota. Temporary disk use remains bounded by the configured uncompressed limits. Abrupt termination such as a killed process can leave temporary files for the operating system to clean up.

## Maintaining version support

`versions.json` registers each supported specification version, its publication state and implemented rule set. `archive/<version>/` holds its exact canonical bundle; `specification/<version>.md`, the schemas in `schema/<version>/` and `tests/fixtures/<version>/` retain its rules, schemas and example projects. `docs/specification.md` and the root schemas are convenience copies for the current version. Build-time checks refuse omitted archive versions, inconsistent catalogs and unimplemented rule sets.

Every binary release must retain support for all specification versions published by that release date. Exact-version dispatch is mandatory; sharing a major number is not evidence of support. Future or unimplemented versions return unsupported. References are embedded at compile time and are never downloaded from an archive-provided URL.

For a new specification version, add its bundle, schema, fixtures and registry entry, implement any new rules, then regenerate its catalog while `released` is false:

```sh
python3 scripts/bundle_catalog.py --write --version 1.1.0
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

## Live library snapshots and incremental backups

Darkbox 1.2.0, 1.3.0, 1.4.0 and 1.5.0 support both ZIP and quiescent directory representations. The
1.0.0 and 1.1.0 specifications and their canonical bundles remain unchanged;
conversion does not upgrade them. All destinations below must be absent.

```sh
darkbox unpack closed.project library
darkbox verify library --limits large --staging-directory /disk/staging
darkbox pack library backup.project --limits large --staging-directory /disk/staging

darkbox delta previous.project backup.project changes.delta --limits large
darkbox verify changes.delta --base previous.project --limits large
darkbox merge previous.project changes.delta restored.project --limits large
```

Applications can keep their SQLite database and media directly in a directory.
Before full verification or packing, stop all writers/workers, prepare closed
DELETE-mode SQLite snapshots without sidecars, and finish metadata and signatures.
Running libraries have no snapshot conformance claim. These commands do not
checkpoint or modify source databases. Never delete WAL files by hand; use the
application's close/snapshot operation. All inputs must remain stable throughout
an operation. Staging and output must be outside input directory packages.

Packing/unpacking preserve every file byte, including manifest, canonical files,
opaque optional data and signatures. ZIP compression, timestamps and explicit
nonempty directory entries can change. Inputs and existing outputs are preserved
on validation failure; new output is validated before publication. The SDK and
these tools require application-controlled parent directories and external
coordination with writers that bypass SDK locks.

Delta participants declare the same stable root manifest `packageId` and common
version 1.2.0, 1.3.0, 1.4.0 or 1.5.0. A transfer contains a `delta.json` descriptor and only changed or
added whole files, including an entire changed SQLite database. It records removed
paths and binds both the exact base manifest and its complete logical file
inventory with SHA-256. The reconstructed target must pass full verification and
match the declared target hashes. A missing/mismatched base blocks the operation.
`verify --base` checks a transfer by reconstructing privately, without publishing.
A transfer verified without its base cannot pass ordinary `verify`.

Apply chains in order using each restored edition as the next base; retain
periodic complete editions and every required intermediate transfer. Delta
creation and merge still read complete editions to verify their contents. Deltas
reduce storage and transfer size, rather than verification cost. They do not
append updates inside an existing ZIP. Protected editions need an externally
trusted signer public key through `--trust-store`; lossless transfer does not
require a private signing key or the decryption keys for unchanged locked content.

## Unsigned inventory inspection

A 1.2.0 producer can include `resourceInventory` in its manifest. SDK writers
rebuild it automatically. It hashes every dynamic file, excluding the manifest,
canonical bundle and detached protection signature; the protection extension
retains its own separate signed inventory. Full `verify` recomputes these hashes.

```sh
darkbox inspect library --inventory-only --limits large --json
```

This fast operation checks safe structure, manifest schema, path coverage and
declared sizes, and exposes the stored hashes in `manifest.resourceInventory`.
Its command is `inventory`, scope is `inventory_claims` and successful status is
`inspected`. It does not read all payload bytes or check CRC, SHA-256, canonical
bytes, SQLite or signatures. No profile validation runs. Missing inventory or
inconsistent claims fail inspection. Exit 0 here means inspection completed;
it does not certify integrity. Unsigned hashes provide no authenticity, and a
cached matching timestamp/size is not proof that a file is unchanged.

## Large media and explicit staging

`--limits default` keeps the conservative defaults. `--limits large` sets the
following bounded policy; individual flags override either preset:

| Limit | Large preset |
| --- | --- |
| ZIP bytes (`--max-archive-bytes`) | 1 TiB |
| Individual uncompressed file (`--max-entry-bytes`) | 64 GiB |
| Total uncompressed bytes (`--max-total-bytes`) | 2 TiB |
| Entry count (`--max-entries`) | 1,000,000 |
| Individual metadata/document bytes (`--max-metadata-bytes`) | 64 MiB |
| Cooperative timeout (`--timeout-seconds`) | 3,600 seconds |

`--staging-directory PATH` selects an existing private storage location without
changing the process environment. Otherwise the operating-system temporary
location is used. Atomic output candidates stay beside the destination. Ordinary
verification streams media without extracting it; SQLite and application callbacks
may require private files. Immutable SDK editing snapshots retain decompressed
resources. Inventory-only inspection does not stage payloads. Allow capacity for
candidate output and any staged databases or protected content. Limits are reader
policy; no archive, profile or delta can raise them. Resource-limit diagnostics
list the relevant override flags and the large preset.

Writers use STORE with 4096-byte data alignment for common already compressed
media suffixes such as JPEG, PNG, WebP and MP4. Other files use DEFLATE. Unaligned
STORE and DEFLATE input remain valid. The SDK's `StoredResource` provides bounded
seekable reads from STORE entries in an immutable verified ZIP, suitable for
serving media byte ranges without extracting it. Protected resource bytes remain
ciphertext; DEFLATE resources require decompression.

## Active or interrupted directory libraries

Directory commands acquire a shared stable sibling lock. An application using
`DirectoryLibrary` holds the exclusive lock while its workers run. Contention,
SQLite sidecars or a WAL-mode main file return status `not_quiescent`, diagnostic
`directory.not_quiescent` and exit code **6**. Reopen the owning application to
recover and seal the library. The CLI never deletes WAL/SHM files or checkpoints
live databases. A leftover unlocked `.darkbox-<digest>.lock` file is normal.
Do not delete it; its inode coordinates later readers and writers.

CLI `verify` still reads every resource. Trusted-digest hooks are an explicit SDK
policy and reports list `trusted_resources`; the CLI does not infer trust from a
manifest inventory. Hot backup and sealing require application coordination and
SQLite connections, so their entry points are in the [SDK](sdk.md#live-directory-storage-130).

For common 1.4.0 or 1.5.0, applications can use the SDK's [short capture barriers](sdk.md#short-capture-barriers-140)
to resume additions and database writes after capture, while retaining captured
resources through streaming. CLI directory commands continue to require a
quiescent source and shared lock for their whole operation.

## Synchronization checkpoints (1.5.0)

`darkbox verify checkpoint.project` recognizes the official required
`studio.illegal.darkbox.sync` extension 1.0.0. It independently replays the complete
causal history, compares the exact logical state/frontier and checks every
historically referenced resource against the actual package inventory. Application
database materialization remains unchecked without its registered profile. The
CLI performs no cloud access and runs no package-supplied projection code.

A live library carrying a `working` sync descriptor returns NotQuiescent (exit 6),
even after SQLite connections close. Generic readers never recover that journal.
The application exports a fresh sealed checkpoint through the SDK; normal exact-base
deltas can transfer those complete editions but do not merge concurrent edits.
See [synchronization integration and limits](sync.md).

For compact synchronization checkpoints, verification checks the root-bound baseline, all subsequent transactions and complete retained resource closure. Pre-generation edits belong to separate recovery archives. Cloud generation scheduling, retention and local rebase are provided through the [SDK](sync.md#compaction-and-bounded-retention).
