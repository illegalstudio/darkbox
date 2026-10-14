# Rust library and selective protection

The `darkbox` crate provides read-only `verify`, `inspect`, `analyze` and configurable `analyze_with`, plus ordinary `open` and validated atomic `save`. `analyze` uses the official protection verifier and an empty trust/key configuration. All runtime checks operate offline. `Error` exposes status, stable code, public resource path and message, implements the standard Rust error interfaces and never contains keys or decrypted plaintext from built-in checks.

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

The current writer preserves the source common version, package identity and protected file/column declarations. Context changes to row identifiers are accepted only with newly encrypted, successfully authenticated blocks. An unchanged block moved to a different row is refused even when keys are absent. Changed blocks cannot reuse a nonce observed under the same key in the source revision, even if that old block is removed. Historical uniqueness across other packages and older revisions remains the nonce allocator's responsibility. Broader declaration/identity or common-version migrations require building and verifying a separate new package; they cannot silently declassify existing content through this API. A newly added required extension must have a registered verifier and writer capability.

The caller MUST coordinate exclusive source/destination access throughout save, such as an application-level writer lock. Source hashes detect observed changes but cannot close a race without caller coordination. Existing source paths can be replaced atomically; a separate destination must be absent and is published without overwriting any file. Symlinks are refused. The writer syncs the candidate, validates it, rechecks the source and publishes atomically, then syncs the parent directory on Unix. Ordinary preparation/verification/conflict failures leave source and any existing destination intact and clean up task staging. A `save.durability` failure means publication occurred but final directory sync failed, so crash durability is uncertain. This is reported distinctly, since a successful rename cannot safely be rolled back without caller coordination.

See [the complete executable example](../examples/protected.rs) and the [normative extension](../archive/1.1.0/docs/darkbox/protection/1.0.0.md) for descriptor, binary format, AAD, trust, failure rules and independent test vectors.
