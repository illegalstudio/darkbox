# Rust library and selective protection

For the complete read/edit/save lifecycle, typed metadata, managed SQLite, resource CRUD and application-profile hooks, start with the [embedding guide](sdk.md). This page documents the compatible lower-level verification, protection and writer APIs.

The `darkbox` crate provides read-only `verify`, `inspect`, `analyze` and configurable `analyze_with`, ordinary `open`, validated atomic `save` and progressive package creation with `PackageWriter`. `analyze` uses the official protection verifier and an empty trust/key configuration. All runtime checks operate offline. `Error` exposes status, stable code, public resource path and message, implements the standard Rust error interfaces and never contains keys or decrypted plaintext from built-in checks.

## Application-owned keys and extensions

```rust
use darkbox::{Limits, Mode, VerificationOptions};
use darkbox::protection::DecryptionKeys;
use zeroize::Zeroizing;

struct Keys;
impl DecryptionKeys for Keys {
    fn key(&self, key_id: &str) -> Option<Zeroizing<[u8; 32]>> {
        // Resolve an authorized identifier using the application's key manager.
        // Returning None means unavailable, not invalid ciphertext.
        let _ = key_id;
        None
    }
}

let keys = Keys;
let mut options = VerificationOptions::default();
options.decryption_keys = Some(&keys);
options.require_protection = true;
// Add public signer keys from application policy, never from the package.
// options.trusted_signers.insert(signer_id, public_key);
let report = darkbox::analyze_with("project.darkbox", Mode::Verify,
    Limits::default(), &options);
```

`VerificationOptions::default()` registers the official protection extension version 1.0.0. Use `ExtensionRegistry::empty()` for an application with no recognized extensions. `register` adds an application-controlled `ExtensionVerifier` with a namespace, exact supported version test and `verify` method. Verification receives an `ExtensionContext` containing the parsed manifest, exact manifest bytes, actual file digests, limits, deadline and a bounded resource-read method over private CRC-checked staging. Required unknown or unimplemented versions return unsupported. Optional unknown extensions are explicitly unchecked.

Custom verifiers can record independent errors and informative diagnoses through `Report::record` and `Report::note`. They must enforce their own version's semantics and honor limits/deadlines; they run trusted application code. Resource-read capability is not permission to execute archive content. `prepare_save` defaults to refusing saves. An extension with writer support implements that callback to synchronize its descriptor and resources. Registration alone does not authorize writing.

`open` runs verification and refuses any status other than passed. A passed result with `key_absent` permits an application-controlled public/locked view, while private values remain unavailable. `inspect` and `Mode::Inspect` retain diagnostic access for unknown required extensions or versions and do not authorize ordinary opening or saving.

## Encrypting before SQLite insertion

`BlockContext` contains a package identity, key identifier and a `BlockLocation::File` or `BlockLocation::Sqlite`. SQLite context includes the database path, table, protected column and stable record identifier. `encrypt_block(plaintext, key, context, nonces)` returns exactly the documented binary block. Bind that returned byte array as a BLOB parameter in a normal SQLite insert/update. The library does not insert plaintext into SQLite, infer application payload types or migrate existing plaintext pages.

Implement `NonceSequence::next_nonce` with a durable nonce allocator belonging to the application's key manager. It must reserve a nonce before returning, coordinate every device using the same actual key, survive crashes and aborted saves, detect exhaustion and respect key aliases. A nonce is 12 bytes; the library intentionally provides no volatile/default allocator that could silently reuse nonces after a restart. Different packages still share the same uniqueness requirement under one key. The deterministic allocator in the example is exclusively for publicly known test keys.

`decrypt_block` validates block structure and AAD, then returns a `Zeroizing<Vec<u8>>` only after successful authentication. It clears its mutable plaintext buffer on normal drop and failure. The caller validates the application profile's types and meanings and controls any subsequent plaintext copies. Keys returned by providers are also zeroizing containers. Built-in package verification decrypts only in memory, drops the authenticated result and reports no plaintext or keys.

## Saving

`save(source, destination, PackageUpdate, limits, options, signer)` verifies the source before editing. `PackageUpdate::manifest` optionally provides candidate metadata. `PackageUpdate::files` maps paths to `Some(already_prepared_bytes)` for replacement/addition or `None` for removal. Manifest and detached signature bytes are writer-owned. Databases must already be coherent, closed SQLite snapshots. Secret updates must already have been encrypted before SQLite insertion or attachment preparation.

Applications supply `ManifestSigner` with signer identifier, public key and a signature callback for exact bytes. The public key must match the externally trusted key under that identifier. A protected save requires the callback even for public-only edits. The writer retains required extension presence/version, invokes recognized extension writer callbacks, preserves unknown optional descriptors/resources, rebuilds the full inventory, serializes final manifest bytes and signs them. It validates the completed ZIP before publication. An unchanged encrypted block may be preserved without keys only in its exact original context. New encrypted bytes require successful authentication with a supplied key. Authentication establishes bytes/context, not application semantics.

The in-memory `save` API preserves the source common version, package identity and protected file/column declarations. Context changes to row identifiers are accepted only with newly encrypted, successfully authenticated blocks. An unchanged block moved to a different row is refused even when keys are absent. Changed blocks cannot reuse a nonce observed under the same key in the source revision, even if that old block is removed. Historical uniqueness across other packages and older revisions remains the nonce allocator's responsibility. Use `PackageWriter` below for complete new editions with resource additions/removals. A newly added required extension must have a registered verifier and writer capability.

The SDK holds a stable advisory destination lock throughout save. The caller MUST coordinate source snapshots and external writers that bypass that lock. Source hashes detect observed changes but cannot close a race with an uncoordinated external writer. Existing source paths can be replaced atomically; a separate destination must be absent and is published without overwriting any file. Symlinks are refused. The writer syncs the candidate, validates it, rechecks the source and publishes atomically, then syncs the parent directory on Unix. Ordinary preparation/verification/conflict failures leave source and any existing destination intact and clean up task staging. A `save.durability` warning in a successful report means publication occurred but final directory sync failed, so crash durability is uncertain. All returned save errors precede publication.

See [the complete executable example](../examples/protected.rs) and the [normative extension](../archive/1.1.0/docs/darkbox/protection/1.0.0.md) for descriptor, binary format, AAD, trust, failure rules and independent test vectors.

## Progressive package creation

`PackageWriter::new(destination, manifest, limits, options, signer)` begins a new package or a complete replacement edition. It automatically streams the exact embedded canonical bundle for the manifest's supported common version. The manifest still declares every required canonical directory and the application folders, databases and public profile document. Supply only dynamic resources, never the canonical files, manifest or signature. Prepared common versions remain usable before publication; published bundles are never edited.

```rust
use darkbox::{Limits, PackageWriter, VerificationOptions};
use std::io::{self, Read};

// manifest is application-prepared serde_json::Value metadata. SQLite is closed
// and coherent, and any protected attachments/BLOBs are already encrypted.
let options = VerificationOptions::default();
let mut writer = PackageWriter::new("project.darkbox", manifest,
    Limits::default(), &options, None)?;
writer.add_path("data/project.sqlite", "prepared/snapshot.sqlite")?;
writer.add_path("docs/profile.md", "prepared/profile.md")?;
let resource = writer.add_reader("assets/generated.bin",
    io::repeat(0).take(16 * 1024 * 1024))?;
assert_eq!(resource.size, 16 * 1024 * 1024);
let report = writer.finish()?;
```

`add_path` accepts a regular filesystem source and copies it into the named ZIP entry. `add_reader` accepts any `Read`, including a borrowed reader, and consumes from its current position through EOF. It supports unknown lengths with ZIP64 and never asks readers to seek or rewind. A 64 KiB buffer feeds compression and SHA-256 together. Each addition returns its actual `EntryDigest`; the writer retains only paths, sizes, hashes and metadata. The caller keeps all source resources stable and captures one coherent application revision. The API performs no SQLite snapshots, encryption, profile migrations or plaintext insertion on the caller's behalf.

Resource/total byte counts, metadata size, entry count, output archive bytes and deadline are bounded, including final manifest/signature and ZIP directory writes. Safe path identity and case-folding checks run during addition. A failed addition poisons the candidate, so catching its error and continuing cannot publish incomplete data. Dropping the writer discards its private candidate. Filesystem staging for final validation is bounded by the normal uncompressed limits. The existing AEAD verifier can buffer one encrypted attachment or SQLite BLOB at a time, up to `max_entry_bytes`; the entire package is never collected in memory. Custom readers/verifiers must return promptly and honor the cooperative deadline.

For protected packages pass a trusted `ManifestSigner` and the decryption provider in `VerificationOptions`. The writer ignores/replaces the input protection inventory, computes a complete sorted inventory from copied bytes, serializes the final manifest and signs those exact bytes. Creating new encrypted blocks requires successful AEAD verification with their keys. An existing destination must first pass verification; its unchanged ciphertext can be retained without decryption keys only with its exact context. Required protection cannot be removed or downgraded. File and database resources may be added or omitted in the next edition, with corresponding updated declarations. A retained encrypted file cannot become an undeclared public resource. Removing a protected column declaration requires removing its containing database resource; the streaming API does not implement column declassification or schema migration. Context or key/identity changes require newly encrypted, authenticated blocks, with nonces distinct from those observed in the previous destination. Historical nonce uniqueness remains application-managed.

All resources for an edition are supplied again, including unchanged resources. Omitted resources are removed. Unknown optional extension descriptors and namespace resource bytes must still be preserved. Recognized extensions explicitly implement `ExtensionVerifier::prepare_streamed_package` to synchronize their descriptors using the complete actual resource-digest map. Its default refuses writing even if `prepare_save` or verification is implemented. Bytes already streamed cannot be rewritten by this callback; applications prepare extension resources before adding them. The official protection extension implements this capability. Callbacks cannot introduce unprepared required extensions or change the protection feature's presence. Final registered verifiers validate the whole candidate.

Before publication `finish` completes and syncs the ZIP, verifies common/canonical/SQLite/extension/protection rules, checks retained ciphertext contexts and source nonces, and rehashes any previous destination. The builder holds a stable advisory destination lock throughout its lifetime; callers coordinate external writers that bypass it. New destinations use no-clobber publication; an existing valid destination is replaced atomically. Every returned `Err` precedes publication and preserves the previous destination. Final parent-directory synchronization on Unix occurs after the atomic commit; if that sync fails the operation returns the published report with a `create.durability` warning, since crash durability is uncertain and the already completed replacement cannot safely be undone. This differs from the legacy `save` post-publication error convention.

Run the [streaming example](../examples/streaming.rs) twice to exercise a generated 16 MiB reader, prepared SQLite/file paths, and removal/addition of a protected resource:

```sh
cargo run --example streaming -- example.project
cargo run --example streaming -- example.project replacement
```

The example uses publicly known test keys and deterministic test blocks; production applications provide durable coordinated nonces and private key management.
