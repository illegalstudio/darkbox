# Protected notes profile

Identifier: `org.example.protected-notes`. Data-format version: `1`.

This fictional example contains `data/project.sqlite` with SQLite `user_version = 1` and one ordinary `notes` table. It requires `studio.illegal.darkbox.protection` version `1.0.0` and Darkbox `1.1.0`.

```sql
PRAGMA journal_mode = DELETE;
PRAGMA user_version = 1;
CREATE TABLE notes (
  id TEXT PRIMARY KEY NOT NULL,
  label TEXT NOT NULL,
  secret BLOB
);
```

`id` is a public, stable, unique nonempty UTF-8 identifier, at most 1024 bytes, compared by exact bytes. It is immutable while retained encrypted bytes refer to it. `label` is public UTF-8 display text. `secret` is SQL NULL for no private value, or one protection block whose plaintext is UTF-8 JSON with object fields `text` (string) and `count` (nonnegative integer). Both fields are encrypted together. No other storage class or plaintext representation is allowed. The extension declares `id` as `recordIdColumn` and `test-key` as the BLOB key identifier. JSON type and count checks are application-profile validation and are not established by generic AEAD authentication.

`assets/public.txt` is a public UTF-8 attachment. `assets/private.bin` is one encrypted protection block for an opaque binary attachment using `test-key`. There are no external references or cross-resource foreign keys. Both assets are mandatory authoritative resources. The archive manifest and this profile remain public, as do record IDs, labels, resource paths, lengths and key/signer identifiers. Encryption does not conceal these metadata.

The example's signing seed and AES key are fixed, publicly known test values. They are not suitable for real private data. The example application supplies the test signer through an external trust file and the AES key through an external key provider/file. Test-key distribution is an example policy only. Real applications manage licenses, passwords, keys, revocation and freshness separately. No live secret belongs in the archive or reports.

Before inserting a private value, serialize it to UTF-8 JSON and encrypt it with a fresh reserved nonce. The ordinary SQLite file stores only public fields and ciphertext BLOBs. A protected project remains inspectable when keys are absent; the private contents remain locked. Ordinary opening requires trusted signature, complete inventory, common checks and recognized required extensions. Saving retains required protection, regenerates the inventory and signs the exact final manifest. Moving a block to another record, column, database, resource path or package identity requires fresh encryption. This profile has no migration or backward compatibility with other data-format versions.
