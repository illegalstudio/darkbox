# Embedding the Rust SDK

The `darkbox` crate covers the supported container lifecycle: verified and diagnostic opening, resource streams, managed SQLite access, staged edits, protected values and attachments, complete editions, atomic saving and export. Applications supply schemas, profile validation, migrations and key policies. Built-in checks operate offline.

```toml
[dependencies]
darkbox = { path = "/path/to/darkbox", default-features = false }
```

Use a registry version when a release containing these APIs is available. The optional default `cli` feature enables the binary and its argument parser. Library integrations can omit both. The crate re-exports `rusqlite`, `serde_json` and `zeroize` for matching SQLite, JSON and secret-buffer types. Rust 1.88 and a C compiler are required for bundled SQLite.

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

`from_reader` accepts any `Read` at its current position, without `Seek`, and bounds the copied ZIP bytes. `path` resolves aliases in parent directories, so its spelling may differ from the supplied filename. Compare resolved paths when checking filesystem identity. Reader-backed packages need `save_as` to select a filesystem destination. `copy_to` streams the exact frozen ZIP to any `Write`; output-stream publication belongs to the caller. `export_resource` atomically exports raw bytes to an absent filename and refuses overwriting. The SDK does not automatically extract archive paths into a user-selected filesystem tree or execute archive contents.

`DiagnosticPackage` runs verification and retains safe resources even when versions, required extensions, signatures, canonical data or application rules prevent ordinary opening. Its report describes failures. Malformed ZIP/manifest data or an incomplete bounded scan can leave no complete resource snapshot; `resource` then returns `package.diagnostic_unavailable`. This handle has no edit/save capability. `Package::open` accepts only a passed report, including valid public/locked views with absent private keys. Its `package.open` error carries the complete verification report in `Error::report`, including distinct signer, signature, version and authentication diagnoses. Candidate verification errors also attach their report. Diagnostic opening additionally exposes safe resource bytes.

Editors retain immutable source evidence and stage replacements as private files with a 64 KiB buffer. `put_reader`/`put_path` insert or replace bytes; failures preserve prior staged bytes. Declare every parent folder first. Path traversal, device names, case collisions and file/folder conflicts are refused. Canonical files, manifest and signature bytes are library-managed. Required profile documentation may be replaced or publicly renamed, but cannot be removed. `remove_resource` also removes matching database/protection declarations and preserves the requirement for at least one database. `remove_folder` requires an empty folder. `update_manifest` changes a copy and checks schema/metadata limits before adoption. Publication checks all resource relationships. Applications update their own references inside databases and documents.

`clone` creates an independent editor checkpoint sharing immutable files. `discard_changes` restores the last opened/saved edition, or initial metadata of a new project. Failed saves retain staged work for retry. `save_as` requires an absent destination and follows the new edition after success. `save` replaces the current original only if its byte digest still matches the opened/saved edition. Stale editors return `package.conflict` and can save isolated work as a separate copy. Missing originals/I/O errors also preserve staged work.

All SDK writers, including `PackageWriter` and legacy `save`, acquire the same stable advisory destination lock. Contention returns `package.busy`. The hidden `.darkbox-<digest>.lock` intentionally remains beside the destination; it is not package content or disposable staging. Keeping its inode prevents a lock race across atomic replacements. Integrating applications coordinate tools that bypass this advisory lock. Package symlinks are refused and parent directories must be application-controlled. Locks cannot prevent unrelated tools from writing files.

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

Configure `Limits` for compressed/entry/total bytes, entry counts, metadata and cooperative deadlines. Set the process temporary directory to suitable storage for large projects. Application SQL, readers, validators and signers must return promptly; the SDK cannot preempt arbitrary blocking callbacks. Application profile validation can intentionally reject an otherwise valid common-format package.
