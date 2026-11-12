# Embedding the Rust SDK

The `darkbox` crate covers the supported container lifecycle: verified and diagnostic opening, resource streams, managed SQLite access, staged edits, protected values and attachments, complete editions, atomic saving and export. Applications supply schemas, profile validation, migrations and key policies. Built-in checks operate offline.

```toml
[dependencies]
darkbox = { version = "1.6.1", default-features = false }
```

Releases are available on [crates.io](https://crates.io/crates/darkbox).
For local SDK development, replace `version` with `path` pointing to its checkout.

The opt-in `exact-numbers` feature preserves arbitrary JSON numbers and enables
`serde_json/arbitrary_precision` plus `jsonschema/arbitrary-precision`. The CLI
enables it. Library consumers using `default-features = false` do not enable
those features through Darkbox. Without it, the strict parser checks numeric
syntax and existing digit/exponent limits, then rejects values whose decimal
value would change on serialization with `Unsupported` / `json.number_precision`.
It never silently rounds unknown extension data. Choose extended precision
explicitly only if the host accepts Cargo feature unification and the associated
Serde enum/flatten implications. Other dependencies may still enable that feature.

The optional default `cli` feature enables the binary and its argument parser. Library integrations can omit both. The crate re-exports `rusqlite`, `serde_json` and `zeroize` for matching SQLite, JSON and secret-buffer types. Rust 1.88 and a C compiler are required for bundled SQLite.

| Operation | API |
| --- | --- |
| Verify/report without retaining resources | `verify`, `inspect`, `analyze_with`, legacy `open` |
| Open an immutable usable edition | `Package::open`, `Package::from_reader` |
| Diagnose unsupported/invalid contents | `DiagnosticPackage::open`, `DiagnosticPackage::from_reader` |
| Enumerate/read raw resource bytes | `resources`, `resource`, `ResourceReader: Read + Seek` |
| Read declared SQLite databases | `database`, `DatabaseReader::with_connection` |
| Start a new project | `ManifestBuilder`, `PackageEditor::new` |
| Edit an existing edition | `Package::edit`, `PackageEditor::clone` |
| Add/replace/remove/rename resources | `put_path`, `put_reader`, `remove_resource`, `rename_resource` |
| Manage folders/metadata | `add_folder`, `remove_folder`, `update_manifest` |
| Snapshot live/in-memory SQLite | `put_database` with an application connection |
| Make transactional SQL edits | `edit_database` |
| Read/write protected attachments | `decrypt_resource`, `put_encrypted`, `rename_encrypted` |
| Read/write protected SQLite values | `decrypt_value`, `encrypt_value`, `put_encrypted_value` |
| Rotate keys/protected package identity | `rekey` |
| Save an edition/new copy | Editor `save`, `save_as` |
| Export resources/exact archive bytes | `export_resource`, `copy_to` |
| Cancel staged work | `discard_changes`, or drop the editor |
| Stream a prepared edition directly to ZIP | `PackageWriter` |
| Validate application rules/extensions | `ApplicationProfile`, `ProfileRegistry`, `ExtensionVerifier` |

## Read, edit and save

```rust
use darkbox::{Package, Limits, VerificationOptions};
use std::io::Cursor;

let options = VerificationOptions::default();
let package = Package::open("project.darkbox", Limits::default(), &options)?;
let mut attachment = package.resource("assets/image.bin")?; // raw Read + Seek
let mut editor = package.edit();
editor.put_reader("assets/new.bin", Cursor::new(b"New resource"))?;
editor.edit_database("data/project.sqlite", |transaction| {
    transaction.execute("UPDATE notes SET label=?1 WHERE id=?2", ["Updated", "r1"])
        .map_err(|_| darkbox::Error::invalid("app.sql", "Update failed"))?;
    Ok(())
})?;
let saved = editor.save(&options, None)?;
assert!(!editor.is_dirty());
```

`Package` freezes compressed input on disk and verifies/extracts that exact snapshot under generated filenames in private staging. Reads never reopen a mutable original ZIP. `manifest`, `report`, `path` and `resources` expose metadata, checked state, an optional original path and actual file digests. `resource` includes manifest, signature and canonical files. It returns ZIP bytes after decompression, including ciphertext, and never implicitly decrypts data. Resource readers and database guards own their backing storage and survive dropping the package/editor or replacing its original file. Staging paths are not exposed.

`from_reader` accepts any `Read` at its current position, without `Seek`, and bounds the copied ZIP bytes. `path` resolves aliases in parent directories, so its spelling may differ from the supplied filename. Compare resolved paths when checking filesystem identity. Reader-backed packages need `save_as` to select a filesystem destination. `copy_to` streams the exact frozen ZIP to any `Write`; output-stream publication belongs to the caller. `export_resource` atomically exports raw bytes to an absent filename and refuses overwriting. The explicit `unpack` conversion validates a complete package before extracting into a private tree and publishing an absent destination. The SDK never executes archive contents.

`DiagnosticPackage` runs verification and retains safe resources even when versions, required extensions, signatures, canonical data or application rules prevent ordinary opening. Its report describes failures. Malformed ZIP/manifest data or an incomplete bounded scan can leave no complete resource snapshot; `resource` then returns `package.diagnostic_unavailable`. This handle has no edit/save capability. `Package::open` accepts only a passed report, including valid public/locked views with absent private keys. Its `package.open` error carries the complete verification report in `Error::report`, including distinct signer, signature, version and authentication diagnoses. Candidate verification errors also attach their report. Diagnostic opening additionally exposes safe resource bytes.

Editors retain immutable source evidence and stage replacements as private files with a 64 KiB buffer. `put_reader`/`put_path` insert or replace bytes; failures preserve prior staged bytes. Declare every parent folder first. Path traversal, device names, case collisions and file/folder conflicts are refused. Canonical files, manifest and signature bytes are library-managed. Required profile documentation may be replaced or publicly renamed, but cannot be removed. `remove_resource` also removes matching database/protection declarations and preserves the requirement for at least one database. `remove_folder` requires an empty folder. `update_manifest` changes a copy and checks schema/metadata limits before adoption. Publication checks all resource relationships. Applications update their own references inside databases and documents.

`clone` creates an independent editor checkpoint sharing immutable files. `discard_changes` restores the last opened/saved edition, or initial metadata of a new project. Failed saves retain staged work for retry. `save_as` requires an absent destination and follows the new edition after success. `save` replaces the current original only if its byte digest still matches the opened/saved edition. Stale editors return `package.conflict` and can save isolated work as a separate copy. Missing originals/I/O errors also preserve staged work.

Starting with software 1.4.2, new ZIP destinations created by `PackageWriter`,
editor `save_as` and legacy `save` publish atomically without overwriting files and
create no persistent output lock. Competing creators may prepare candidates, but
only one can publish; a destination that appears during setup is never adopted
as a replacement. Successful, failed and abandoned new exports leave no lock file.

Writers replacing existing ZIPs acquire the same stable advisory destination
lock. Contention returns `package.busy`. The hidden `.darkbox-<digest>.lock`
intentionally remains beside an existing-file replacement destination; it is not
package content or disposable staging. Keeping its inode prevents a lock race
across atomic replacements. Directory-library locks retain their separate
whole-session protocol. Existing lock files are not automatically deleted. Integrating applications coordinate tools that bypass this advisory lock. Package symlinks are refused and parent directories must be application-controlled. Locks cannot prevent unrelated tools from writing files.

Software 1.6.0 explicitly releases replacement locks when the owning writer ends,
including when a concurrently spawned child temporarily inherits a descriptor.
The stable lock inode remains in place.

Publication streams a complete candidate, rebuilds inventory/signature, validates common/canonical/SQLite/extension/profile rules, checks encrypted contexts, rechecks destination bytes and commits atomically. The editor prepares its new frozen snapshot before replacement; post-commit reopening cannot turn a published save into an error. Every editor save error precedes publication and preserves an existing destination. Success may carry `create.durability` if final Unix directory synchronization failed after publication.

## Managed SQLite

`database` exposes only manifest-declared databases through read-only connections, defensive mode, untrusted schema, disabled extension loading and configured SQLite limits. `DatabaseReader::with_connection` installs a fresh deadline for each operation in a long-lived application. Low-level `connection` uses the guard's installed deadline. Returned row values belong to the application. Archive-provided SQL, profile text and binaries are never executed as integration instructions.

`put_database(DatabaseDeclaration, &Connection)` uses incremental SQLite backup to capture coherent committed data, including WAL-backed and in-memory sources. Active source write transactions/competing locks may return `package.database_busy`; retry after committing. The closed snapshot is normalized to DELETE journal mode and checked for integrity, foreign keys, logical tables and declared `user_version` before staging with its declaration. Source connections remain application-owned. Raw `put_path` requires an already coherent snapshot; copying a live WAL database's main file is not a substitute.

`edit_database` runs trusted application SQL in one transaction on a private copy, with foreign keys enabled, bounded pages/cache/SQL/value sizes and a deadline. Callback, commit or structural/inventory failure discards the copy and its journals. Successful edits become a closed snapshot. Schema/`user_version` changes must match candidate metadata supplied through `update_manifest`; the application updates its profile document. The SDK does not invent migrations. Encrypt secrets before binding to SQL: later encryption cannot erase plaintext already present in pages or journals.

## Construct and protect projects

`ManifestBuilder::new(common_version, profile_id, data_version)` declares exact-version canonical directories and defaults the public profile path to `docs/profile.md`. Add folders, typed `DatabaseDeclaration`/`TableDeclaration`, optional creator metadata and namespaced extensions. `protection(ProtectionData)` adds the official required descriptor and its folders. `build` validates the metadata schema; publication checks actual files/databases. Metadata and documentation alone do not guarantee application conformance.

`KeyRing` is a zeroizing in-memory `DecryptionKeys` provider with insert/remove/contains methods. `Ed25519Signer::from_seed` accepts a zeroizing seed and implements pure Ed25519 `ManifestSigner`. Replace either with application secure key storage/external signing when appropriate. Trust is supplied separately through `VerificationOptions::trusted_signers`; secrets are never serialized or automatically distributed. `NonceSequence` remains an application-owned durable allocator.

`put_encrypted` encrypts before staging and updates the file declaration using current package identity/path/key ID. `encrypt_value(ValueAddress, ...)` creates ciphertext for a declared column/record ID before insertion. `put_encrypted_value` encrypts and transactionally replaces exactly one existing value. Missing/nonunique IDs fail. `decrypt_value` returns `None` for SQL NULL and authenticated zeroizing bytes for a BLOB; absent keys and missing records are distinct errors. `decrypt_resource` authenticates a declared attachment. Each operation bounds one block in memory.

`rename_resource` handles public resources and updates database/profile paths. `rename_encrypted` authenticates and re-encrypts an attachment for its new path with a fresh nonce, preserving staged state on failure. Protected database/record/schema changes require application migrations and fresh blocks. Moving ciphertext blindly fails publication. `rekey(new_package_id, old_to_new_key_ids, keys, nonces)` re-encrypts every protected file/non-NULL SQLite value and adopts the entire staged edition atomically. Supply old/new keys. An empty mapping can change package identity; an unchanged identity can rotate keys. Failure preserves the editor while reserved nonces remain consumed. Saving still requires trusted signing capability.

Unknown optional extensions retain exact descriptors, namespace folders and bytes. Required extensions retain presence/version and need streaming writer capability. Unchanged ciphertext may be copied/publicly edited without private keys only if its context is unchanged. New/changed blocks require successful authentication before publication. Retained protected columns cannot silently become public. See [the low-level protection documentation](library.md) for binary format, AAD, nonce allocation, external trust and extension writer capabilities.

## Application profile hooks

Register trusted `ApplicationProfile` implementations in `VerificationOptions::profiles`. Each declares an ID, supported data-format versions and `validate(ProfileContext)`. Validation runs only after common, SQLite and required-extension checks pass. Context provides manifest, digests, limits/deadline, resource streams, read-only database access and explicit decryption. Code comes from the application, never the archive. Callbacks honor deadlines and define their policy for missing keys.

Success sets `application_validation = "passed"` and adds `profile.application`. Callback errors block opening/publication and set `failed`. With `require_profile = true`, an unregistered exact profile version yields `profile.unsupported` and `application_validation = "unsupported"`; otherwise no validator leaves `not_performed`. Built-in AEAD checks retain `plaintext_validation = "not_performed"` for each block; application certification belongs to the profile callback. The CLI has no built-in application validators.

The SDK covers container mechanics for supported common versions. Application meaning, reference repair, licensing, passwords, migrations, distributed key management and historical nonce uniqueness remain application capabilities. Future common versions/unknown required extensions permit diagnostic access and cannot be saved as if supported.

See the executable [lifecycle example](../examples/lifecycle.rs) and [embedded profile](../examples/profiles/sdk-notes.md). It creates public/protected projects, streams an attachment, snapshots SQLite, registers a profile, reopens, edits, renames, saves and reads through public SDK APIs.

```sh
cargo run --example lifecycle -- public.project
cargo run --example lifecycle -- protected.project protected
```

All example keys and deterministic nonces are public test data, unsuitable for production.

## Storage and limits

Packages/editors/writers never accumulate the entire archive in memory. Resource I/O uses 64 KiB buffers. AEAD can buffer one encrypted attachment/BLOB and its plaintext under `max_entry_bytes`; JSON/reports retain bounded metadata. Compressed snapshots, uncompressed staging, replacements and candidate validation need disk space. Retained old handles can keep several editions alive. Dropping the final resource/database/package/editor owner removes private storage. Normal failures clean owned candidates/journal directories. Abrupt termination can leave operating-system temporary files.

Configure `Limits` for compressed/entry/total bytes, entry counts, metadata and cooperative deadlines. Set `Limits::staging_directory` to an existing private directory on suitable storage for large projects; `None` uses the operating-system temporary directory. Output candidates remain beside the destination for atomic publication. `Limits::large()` provides a bounded media-library preset, with individual fields still controlled by the application. Application SQL, readers, validators and signers must return promptly; the SDK cannot preempt arbitrary blocking callbacks. Application profile validation can intentionally reject an otherwise valid common-format package.

## Directory libraries and incremental editions (1.2.0)

Use `ManifestBuilder::package_id(id).resource_inventory()` to opt into stable
library identity and an unsigned resource inventory under common version 1.2.0.
The builder's `build` validates structure; `PackageWriter` and editor publication
recompute actual inventory digests before signing the final manifest. Root
`packageId` must match the protection extension's package ID when both are used.
SDK writers preserve existing common versions; conversion never invents migrations.

`analyze_with`/`verify` and `inspect` accept quiescent directories as well as ZIPs.
Directory reports use compression `none`, `crc_verified = false`, and
`directory.structure`/`directory.bytes` checks. Full verification still streams
all files, compares canonical bytes and hashes, and checks isolated SQLite
snapshots. Running working directories are application-owned; stop every writer,
normalize and close SQLite to DELETE mode, and finish metadata/signatures before
claiming snapshot conformance. Source inputs must remain stable throughout an
operation. Staging/output locations must be outside every input directory.

The lossless APIs accept `Limits` and `VerificationOptions` and return `Report`:

```rust
use darkbox::{Limits, VerificationOptions};
let limits = Limits {
    staging_directory: Some("/disk/private-staging".into()),
    ..Limits::large()
};
let options = VerificationOptions::default();
darkbox::unpack("snapshot.project", "library", limits.clone(), &options)?;
darkbox::pack("library", "backup.project", limits.clone(), &options)?;
darkbox::create_delta("snapshot.project", "backup.project", "changes.delta", limits.clone(), &options)?;
darkbox::verify_delta("snapshot.project", "changes.delta", limits.clone(), &options)?;
darkbox::merge("snapshot.project", "changes.delta", "restored.project", limits, &options)?;
```

All output destinations must be absent. Conversion/reconstruction preserve exact
manifest, signature, canonical and opaque resource bytes. ZIP representation
metadata need not survive. Required extension versions cannot disappear in a
delta. A transport delta is not a standalone project; it requires its exact base.
Chains apply one link at a time to the preceding verified complete edition.
Readers check base/target manifest and full logical-inventory hashes, all transport
CRCs, exact changed/removed paths and the fully reconstructed target before
publication. Signed copies need external public trust, without signing keys.
SQLite changes transfer whole database files. Complete editions are still read
for verification; unchanged ordinary media is streamed without private copies.

`Package::open` also accepts quiescent directories for common versions 1.2.0, 1.3.0, 1.4.0 and 1.5.0. It packs and freezes a
private ZIP, then retains its verified resource snapshot. That immutable handle
has `path() = None`; edits require `save_as` to a new ZIP. It does not write staged
edits back into a live directory. Applications own live SQL/media operations and
quiescence, and use `pack` for backup snapshots. `DiagnosticPackage::open` can
report invalid directory checks without an editable handle. Unsafe/incomplete
inputs may have no complete diagnostic resource snapshot.

`inspect_inventory(path, limits)` returns an `inspected` report with scope
`inventory_claims`, never `passed`. It checks structure, schema, path coverage and
size claims from optional `resourceInventory` without reading all payloads. It
explicitly leaves CRC, SHA-256, canonical bytes, SQLite, signatures and profiles
unchecked. Applications may reuse trusted cached verification results only when
they independently guarantee object immutability; timestamps/sizes alone are
insufficient. This API is not an integrity gate for opening or saving.

`StoredResource::open(zip_path, entry_path, limits, options)` fully verifies an
archive through the same open file descriptor and returns bounded `Read + Seek`
access to a STORE entry, with `len`, `is_empty`, `data_offset` and `report` methods.
The caller must prevent archive mutation for the lifetime of this handle. Ordinary
media is not copied or extracted; databases and registered callback requirements
may still use staging. Protected entries expose raw ciphertext. DEFLATE entries
return `media.compression`; use ordinary package resource access to decompress.
Writers STORE and align common compressed media to 4096 bytes, while readers
also accept unaligned inputs. ZIP64 sizes and offsets remain 64-bit throughout.

Extension verifiers can override `resources_to_stage(manifest)` to return a set of only
resources they read from staging, computed once per scan. Digests always cover every file. Returning `None` by default
retains access to every resource for existing custom verifiers; the built-in
protection verifier stages its signature, encrypted files and declared databases,
leaving ordinary public media streaming. Registered profile validators retain
access to all resources. Staging limits and cleanup apply to every path.

## Live directory storage (1.3.0)

`DirectoryLibrary` owns the exclusive interoperable sibling lock for a whole
working session. `initialize(path, manifest, profile, limits)` creates absent
storage directly with the canonical bundle and declared folders. Supply a 1.3.0, 1.4.0 or 1.5.0
manifest with a stable `packageId`, then create its databases and resources while
holding the returned handle. Initialization alone is not snapshot validation.
`open(path)` also opens interrupted working storage so the owning application can
recover it. It takes the lock without automatically modifying or validating data.

Stop workers, finish transactions, use SQLite to recover/checkpoint and set DELETE
mode, then close every connection. `seal(manifest, limits, options)` consumes the
handle, refreshes an optional resourceInventory, checks the complete candidate and
atomically updates the manifest. It releases the lock on return. Failed validation
preserves the previous manifest; reopen the handle to continue recovery. Update
`application.formatVersion` and the corresponding profile document together.
The stable lock file is never deleted and remains outside package inventory.

```rust,no_run
use darkbox::{DirectoryLibrary, Limits, VerificationOptions};
use std::collections::BTreeMap;
# fn example(manifest: darkbox::serde_json::Value, db: &darkbox::rusqlite::Connection) -> Result<(), darkbox::Error> {
let mut library = DirectoryLibrary::open("library")?;
let databases = BTreeMap::from([("data/library.sqlite".to_owned(), db)]);
// Hold the application's coherent write/deletion barrier throughout each call.
library.hot_backup("backup.project", manifest.clone(), &databases,
    Limits::large(), &VerificationOptions::default())?;
library.create_delta("previous.project", "changes.delta", manifest, &databases,
    Limits::large(), &VerificationOptions::default())?;
# Ok(()) }
```

Hot operations require exactly one application-supplied connection for each
manifest database. SQLite backup captures committed WAL state into private
DELETE-mode copies. Live files and sidecars are unchanged. Media stream from the
library under the application's barrier; the lock does not pause its threads.
`create_delta` accepts an empty connection map for a closed quiescent library.
It verifies the base and an overlaid target view, then writes changed files only;
it never materializes an entire target ZIP or stages ordinary media.

`TrustedDigests::sha256(path, size)` can provide a cached hash for resources whose
unchanged bytes the application independently guarantees. Set
`VerificationOptions::trusted_digests` explicitly. Return `None` for full reads.
Common 1.3.0, 1.4.0 and 1.5.0 directories support this optimization. Metadata, canonical documentation,
profile text, databases and protected or callback-staged resources remain fully
read. A small signature prefix is still checked for uninventoried databases.
Caches may never come from untrusted manifests or timestamp comparisons alone.

Conditional reports retain `Status::Passed` with scope
`common_checks_with_trusted_resources`, check `directory.incremental` and the
exact `trusted_resources` list. Delta reports retain that list with their delta
scope. Default options perform full verification. Copied output bytes are always
rehashed, so a stale cached hash cannot publish mismatching changed resources.
An unchanged file omitted from a delta depends on the application's cache trust;
reconstruction verifies the complete result against the exact base.

The live APIs preserve common version, packageId and extension descriptors.
Protected manifest changes require a transactional extension-aware application
writer and are rejected by these new convenience methods. Exact sealed protected
packages continue to support `pack`, `unpack`, `create_delta` and `merge`, including
locked copying without decryption. Use caller-supplied profile verifiers to enforce
application semantics; hot capture never implies cross-resource transactions.
All staging must be outside the library. Atomic candidates stay beside outputs.

## Short capture barriers (1.4.0)

Use `DirectoryLibrary::prepare_hot_capture(manifest, connections, limits)` while
holding the application's coherent write barrier. It snapshots every database,
reads the profile and freezes the listing, sizes and identities without hashing
or copying media. Returning `HotCapture` signals that the short barrier can end.
The owned capture keeps its lock and private snapshots alive independently of
the original library handle. It is `Send` and can move to a worker. Retain every
captured external resource unchanged until the capture handle finishes or drops. Defer deletions of referenced media;
new media additions and live database writes may resume immediately.

```rust,no_run
# fn example(library: &darkbox::DirectoryLibrary, manifest: darkbox::serde_json::Value, connections: &std::collections::BTreeMap<String, &darkbox::rusqlite::Connection>) -> Result<(),darkbox::Error> {
// Hold the application write barrier for this call only.
let capture = library.prepare_hot_capture(manifest, connections, darkbox::Limits::large())?;
// Release the write barrier. Keep captured external resources immutable/retained.
capture.write_backup("edition.project", &darkbox::VerificationOptions::default())?;
// A separate capture can instead call write_delta(base, destination, options).
# Ok(()) }
```

`write_backup` and `write_delta` consume the handle. They never enumerate the live
directory again. The database, profile and manifest revision stay captured even
if the application updates their live paths. Retained resources are checked by
size/type, modification time and, on Unix, device/inode identity. Copied bytes
remain hash-checked. A violated retention contract fails without publishing.
The timeout covers capture and streaming, including time between API calls.
Capture guards release their private snapshots on drop. Existing one-call APIs
retain their whole-call coordination contract for common 1.3.0; the new split
contract requires common 1.4.0 or 1.5.0. Protected live metadata rewriting retains its
existing capability restriction.

## Offline causal synchronization (1.5.0)

The `darkbox::sync` module supplies immutable domain/profile registration, exact
causal history, conflict-preserving registers and sets, ordered placements, private
object storage, durable transactional queues, exchange scans, full checkpoints and
bootstrap. Applications implement the pinned `SyncProjection` adapter and commit
synchronized edits through `SyncSession`. See [the complete integration guide](sync.md)
and [runnable example](../examples/sync_notes.rs).

`VerificationOptions::default` registers `SyncVerifier`. Generic sealed-checkpoint
verification checks causal replay, logical state and every historical resource
digest, with application materialization explicitly unchecked without a profile
adapter. Working sync metadata returns NotQuiescent to ordinary readers; use
`SnapshotBuilder` for complete portable editions. Protocol 1.0.0 uses trusted-folder
plaintext, fixed profiles and retained history without automatic deletion. It
refuses protected libraries without downgrading their protection.

Repository synchronization supports compact checkpoint generations, bounded retention without device membership, and private stale-base recovery. Use `SyncRepository::open_session` and its guarded exchanges, and preserve local columns with `SyncProjection::copy_local`. See [the synchronization guide](sync.md#compaction-and-bounded-retention).

Software 1.6.0 also provides `OwnedSyncSession` and
`SyncRepository::open_owned_session` for long-lived application state. They expose
the same operations and rebase checks as borrowed sessions; `close` returns the
still-guarded library. Failed opening returns `OwnedSessionError`, whose
`into_parts` recovers both the error and library. `Dot` and `Counter` implement
`Hash` for application maps and sets.

`receive_exchange` compares exact transaction identities and retains fork evidence
before skipping objects of already applied transactions. Pending transactions
continue importing objects that arrive later. For private stores with an
application-enforced immutability contract,
`ObjectStore::with_trusted_immutable_cache(capacity)` explicitly enables bounded
verification reuse shared by cloned handles. Ordinary stores retain full hashing;
`ObjectStore::verify` always hashes all bytes and `clear_verification_cache`
invalidates shared witnesses. See [object verification policy](sync.md#object-verification-policy).

Sync publication on Unix mounts without hard links or no-replace rename is
available in software 1.6.1 when directory locks and atomic rename are supported.
See [filesystem requirements](sync.md#filesystem-requirements) for the local
coordination and cloud-client boundaries.
