# Changelog

Software versions (the `darkbox` crate and command-line tool) and specification versions are independent. Each entry names the specification versions it publishes. Published specification versions are never changed afterwards.

## Unreleased

### Changed

- Specification versions 1.0.0 to 1.4.0 are read-only for new packages. Every version is still read and verified, and existing packages of those versions are still saved in place or as a copy. `PackageWriter`, `PackageEditor` and `DirectoryLibrary::initialize` refuse to start a new package in them with the unsupported error `version.retired`. New packages use 1.6.0, or 1.5.0 for existing sync 1.0.0 domains. This changes behavior for callers that created packages in the retired versions; `VerificationOptions::with_retired_versions(true)` restores it for package writers.
- `versions.json` has a `writable` flag per version, `SpecificationVersion` exposes it, and `darkbox versions` marks read-only versions.
- The cryptographic dependencies are upgraded together: `aes` 0.9, `aes-gcm` 0.11, `sha2` 0.11 and `ed25519-dalek` 3.0. They are internal to the crate, so the public API is unchanged, and the protection test vectors confirm that encrypted blocks, signatures and digests are byte-for-byte the same. `aes-gcm` is built without its operating-system random source, which Darkbox never used: nonces and keys come from the caller.
- `clap` is updated to 4.6.9 and `jsonschema` to 0.63.

### Fixed

- The sync concurrency test that failed intermittently on Windows was a test defect, not a library defect. Its background publisher waited at most five seconds for the database write lock while the main thread edited in a tight loop; SQLite polls for a busy lock instead of queueing, so on slow storage the wait could expire. The test now waits long enough, and the [sync guide](docs/sync.md) explains which busy timeout a background publisher needs.

### Documentation

- The [profile guide](docs/profiles.md) recommends durable formats for application content: UTF-8 plain text or Markdown for prose, documented text-based markup for rich text, JSON or columns for structured values, and openly specified media formats. These are recommendations for profile authors; the common specification still does not restrict resource formats.

## Software 2.0.0 (2026-11-25)

Publishes common specification **1.6.0**, the separate extension bundles **protection 1.0.0** and **sync 1.1.0**. Earlier specification versions and their canonical bundles are unchanged and remain supported.

### Specification 1.6.0

- Documentation of official extensions is no longer part of the common canonical bundle. Each official extension version has its own canonical bundle with its own catalog, included only in packages whose manifest declares it. A new extension version no longer requires a new common version, and a package without extensions carries about 186 KB of documentation instead of 507 KB.
- The live-directory lock is defined for Windows (`LockFileEx` over the whole file) as well as for Unix-like systems (`flock(2)`).
- Sections are numbered 1 to 14 without gaps, and the text no longer refers to one implementation's dependencies, field names or exit codes.
- Corrected statements inherited from 1.5.0: the number of canonical folders, the description of a package as only a ZIP archive in the canonical README, and the canonical file table.
- Sync extension 1.1.0 records in `commonVersion` the lowest common version of a domain's packages instead of one exact version. Its protocol is otherwise identical to 1.0.0. Sync 1.0.0 stays bound to common 1.5.0, and existing domains keep working unchanged.

### Breaking changes in the Rust API

- Public types that can grow are `#[non_exhaustive]`. Struct literals and `..Default::default()` no longer compile outside the crate. Use the constructors and `with_*` builders instead, for example `Limits::default().with_max_entries(100)`, `VerificationOptions::default().with_decryption_keys(&keys)`, `PackageUpdate::default().with_file(path, bytes)`, `DatabaseDeclaration::new(..)`, `TableDeclaration::new(..)`, `RebaseTarget::new(..)`, `ResolutionTarget::new(..)` and `LocalProjection::new(..)`. Fields stay public and assignable. Protocol records keep their exact shape.
- Report vocabularies are enums instead of strings: `Scope`, `ApplicationValidation`, `Severity`, `EntryKind`, `Compression`, and `SignatureStatus`, `AuthenticationStatus`, `PlaintextValidation` in `darkbox::protection`. They serialize to the same text and still compare with `&str`.
- `Report::cli_version` is removed from the library. The command-line tool adds `cli_version` to its own JSON output, which keeps report version 2 and the same keys.
- `sync::VERSION` is replaced by `sync::SyncProtocol`. `Domain::generate` and `Domain::new` take the protocol as their first argument, and a domain keeps it forever.
- `supported_versions()` yields `SpecificationVersion` values instead of tuples.
- Resource-limit messages from the library no longer name command-line options; the tool appends its own hint.
- The minimum supported Rust version is 1.89.

### Security

- `rusqlite` is updated to 0.43, whose bundled SQLite is not affected by RUSTSEC-2026-0459 (uninitialized page-cache memory when a database is opened together with a crafted `-wal` file). Darkbox never opens a packaged database together with a sidecar, so sealed packages were not an attack path, but the fix removes the exposure for working directories as well.
- `zip` is updated to 9.8, which resolves seven advisories in its extraction, stream-reading, legacy-compression and AES code (RUSTSEC-2026-0367, 0368, 0369, 0429, 0545, 0547 and 0548). Darkbox does not use those code paths: it reads entries by index after its own structural checks.
- Both were found by the new `cargo deny` check. Because `rusqlite` is re-exported, its upgrade is part of the breaking changes of this release.

### Fixed

Found by the first test runs on Windows:

- Published files are flushed through a writable handle. Flushing a read-only handle fails on Windows, which made sync publication, checkpoint sealing and rebase fail with access denied.
- `save` closes its source archive before replacing it in place.
- Sync scanning, recovery export and retention build protocol paths with `/` on every platform. With native separators, records were ignored or rejected on Windows.

### Added

- `supported_extensions()`, and extension bundles in the output of `darkbox versions`.
- `Report::from_failure`, `Domain::protocol`, and documentation for every public item (`missing_docs` is enforced).
- A language-neutral [conformance corpus](conformance/README.md) of 48 packages with their expected outcome.
- Fuzz targets in `fuzz/`, a dependency policy in `deny.toml`, Dependabot configuration and a [security policy](SECURITY.md).
- Windows is tested in CI and the whole suite runs there. It is not a release target yet: one sync concurrency test still fails intermittently with a locked database, so the job does not block.

### Changed

- The capabilities of each specification version are declared once in `versions.json` instead of being repeated in the code.
- The analysis code is split into phases in `src/analysis.rs`.
- File locks use the Rust standard library. The `fs2` dependency is removed; lock behavior on Unix is unchanged.
- The examples build common 1.6.0 packages.

### Migration

1. Replace struct literals of `Limits`, `VerificationOptions`, `PackageUpdate`, `DatabaseDeclaration`, `TableDeclaration`, `SessionOptions`, `RebaseTarget`, `ResolutionTarget` and `LocalProjection` with the constructors and builders above.
2. Pass a `SyncProtocol` when creating a domain. Use `SyncProtocol::V1_0` to keep writing common 1.5.0 packages, or `SyncProtocol::V1_1` together with common 1.6.0 manifests. Existing domains report their own protocol through `Domain::protocol()` and need no change.
3. Replace reads of `Report::cli_version` with your own software version.
4. To write 1.6.0 packages, build manifests with `ManifestBuilder::new("1.6.0", ..)`. Declaring an official extension through the builder also declares its documentation folders, and the writers add the bundle files.

## Software 1.6.2 (2026-11-13)

- Documentation only: maintainer release instructions moved out of the public README.

## Software 1.6.1 (2026-11-12)

- Sync publication works on Unix mounts without hard links or no-replace rename, when directory advisory locking and atomic rename are available.
- Object witnesses are invalidated when link counts change.

## Software 1.6.0 (2026-11-12)

- Owning sync sessions, receipt without rereading applied media, and explicit bounded verification reuse for private immutable object stores.
- Destination locks are released before descriptor closure.

## Software 1.5.0 (2026-11-11)

Publishes specification **1.5.0**.

- The required-when-present synchronization extension 1.0.0: immutable causal transactions, explicit merge rules for concurrent values, sets, deletions and ordering, complete checkpoints, compact generations and membership-free bounded retention.
- Private recovery packages preserve unpublished edits of old installations before a rebase.

## Software 1.4.2 (2026-11-09)

- New ZIP exports are published without persistent sibling lock files. Replacements of existing ZIPs and live directories keep writer coordination.

## Software 1.4.1 (2026-11-09)

- Documentation aligned with crates.io publication and retained captures.

## Software 1.4.0 (2026-11-09)

Publishes specification **1.4.0**.

- `HotCapture`: snapshot databases, metadata and the resource listing under a short write barrier, then stream a backup or delta while the application resumes work.
- The crate is published on crates.io. Extended JSON number precision is the explicit `exact-numbers` feature.

## Software 1.3.1 (2026-11-09)

- Test fix for lock parent aliases.

## Software 1.3.0 (2026-11-09)

Publishes specification **1.3.0**.

- Coordinated live directory storage with an interoperable lock and a distinct `not_quiescent` outcome.
- The SDK initializes and seals libraries directly, backs up active SQLite connections and creates deltas without a complete target ZIP. Application-trusted digests are explicit in reports.

## Software 1.2.0 (2026-11-09)

Publishes specification **1.2.0**.

- Quiescent directory packages, an optional unsigned resource inventory, and delta transfers between complete editions (`pack`, `unpack`, `delta`, `merge`, `verify --base`).
- A large-library limit preset, explicit staging storage and seekable access to STORE media.

## Software 1.1.0 (2026-10-14)

Publishes specification **1.1.0**.

- The official protection extension 1.0.0: selective AES-256-GCM encryption of attachments and SQLite values, an Ed25519 manifest signature and a signed SHA-256 inventory.
- A complete Rust SDK for reading, editing and atomically saving packages.

## Software 1.0.0 (2026-10-13)

Publishes specification **1.0.0**.

- The common specification: ZIP container, JSON manifest, SQLite snapshots, canonical documentation bundle and application profile documentation.
- The `darkbox` command-line tool with `verify`, `inspect` and `versions`.
