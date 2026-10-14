# SDK notes profile

Profile identifier: `org.example.sdk-notes`.
Application data-format version: `1`.

`data/notes.sqlite` is a coherent ordinary SQLite snapshot with `user_version = 1`.
The `notes` table contains one example record. `id` is a unique, nonempty, stable
TEXT identifier. `label` is public, nonempty TEXT. `secret` is NULL in a public
project and an authenticated encrypted BLOB in a protected project. Its plaintext
is UTF-8 note text, without a BOM or an additional binary header.

`assets/` contains opaque byte resources. Public resources are readable directly.
Files named in the official protection descriptor contain encrypted opaque bytes;
their current paths and key identifiers are defined by that descriptor. A rename
of a protected resource requires a fresh block authenticated for the new path.
The protection descriptor identifies the stable package identity and the `notes`
protected column, with `id` selecting the exact immutable record identifier.

This executable example registers an application validator that checks the public
label and, when protection is present, authenticates the private value and checks
its UTF-8 type. It requires private keys for that profile validation. Other
applications may define a different policy for partial validation without keys.

All example encryption keys, signing seeds and deterministic nonce sequences are
public test data. They provide no production confidentiality or trust.
