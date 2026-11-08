# Darkbox 1.2.0 library representations and transfers

## 13. Quiescent directory representation

A Darkbox 1.2.0 package MAY be a directory containing exactly the same files,
relative paths and canonical bytes as its ZIP representation. The root contains
manifest.json and README.md, without an enclosing version directory. All folder,
path, inventory, profile, SQLite, extension and protection rules apply. ZIP header,
compression and CRC requirements apply only to ZIP representations. Directory
readers MUST read every file for full verification; absence of a ZIP CRC does not
permit skipping SQLite, canonical or cryptographic checks. Symbolic links and
special entries are forbidden, including at the root. Empty declared folders
MUST exist. Filesystem timestamps and permissions have no project meaning.

A directory is conformant only at a quiescent boundary: all application writers
and workers have stopped, every database is a closed self-contained DELETE-mode
snapshot without journal/WAL/shared-memory sidecars, and metadata, inventories
and signatures describe those exact bytes. An active directory is working
storage and makes no conformance claim. Applications MAY use WAL and temporary
working data while active. They MUST coordinate exclusive access while preparing,
verifying, packing or unpacking a snapshot. Tools MUST NOT delete sidecars or
silently checkpoint application databases. A snapshot of a running database MUST
use SQLite's backup API or equivalent application-coordinated snapshot facilities.
Copying a WAL database's main file alone is insufficient.

Packing and unpacking MUST preserve the relative file inventory and every file's
bytes, including the exact manifest, unknown optional data and signatures.
Compression, entry order, explicit nonempty ZIP directory entries, permissions
and timestamps need not round-trip. Conversion does not migrate common or
application versions and does not require signing keys. Tools MUST validate a
candidate before publication and MUST NOT overwrite an existing destination
without a separately authorized replacement operation. Parent directories and
input quiescence remain caller-controlled.

## 14. Library identity and optional unsigned inventory

The optional root manifest `packageId` is a stable, application-assigned library
identity, matching `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. Producers SHOULD use a random
UUID. Different independent libraries MUST have different identities. An edition
retains its library identity; an independent copy MAY receive a new identity via
an explicit application operation. This identifier is not a signature, content
hash or proof of ownership. A delta participant MUST declare it. A protected
package that also declares this root field MUST use the same value for the
protection extension's `data.packageId`.

The optional root `resourceInventory` array contains objects with exactly `path`,
`size` (nonnegative byte length) and `sha256` (64 lowercase hexadecimal digits).
When present, it MUST cover every dynamic regular file exactly once, including
databases, profile documents, application resources and extension resources.
It MUST exclude manifest.json, the canonical catalog, all canonical bundle files
and the official detached protection signature. These exclusions avoid circular
hash dependencies. Producers MUST update it whenever covered bytes change.
The signed protection extension retains its separate complete payload inventory
and signature requirements. Unsigned inventory is optional; full verification
MUST compare every declared digest and size with actual bytes if it is present.

A tool MAY expose a quick inventory inspection that checks structure, schema,
path coverage and declared sizes without reading all payload bytes. Such a report
MUST explicitly state that CRC, hashes, canonical bytes, SQLite, signatures and
application semantics were not verified, and MUST NOT report a verified package.
The inventory itself is untrusted. Matching path, size or modification time does
not prove bytes unchanged. Incremental re-verification MAY reuse trusted cached
results only if the application can independently guarantee unchanged bytes, for
example through immutable, application-controlled objects. Full common verification
remains a complete byte pass. Unsigned hashes provide no authenticity.

## 15. Delta transfers

A delta is a separate ZIP transfer envelope, not a conformant standalone project.
It applies one exact complete base edition to produce one exact complete target
edition. Both editions MUST be conformant Darkbox 1.2.0 packages with the same
`packageId`. Delta envelope version `1.0.0` is independent of software and common
specification versions. A delta MUST NOT remove or change the version of a
required extension present in its base. Application migrations that produce the
target remain application responsibilities.

The envelope MUST obey the common safe ZIP/path rules, including STORE/DEFLATE,
ZIP64 support, unique names, no aliases, no encryption, no links and CRC checks
for every entry. Its regular files are exactly root `delta.json` and
`files/0`, `files/1`, ... for each changed path. The optional explicit `files/`
directory is its only permitted directory entry and MUST be absent when there
are no changed files. No canonical bundle is required inside this transfer
because unchanged canonical bytes are inherited from the verified base.

`delta.json` is UTF-8 JSON without a BOM or duplicate keys. It has exactly these
fields, with no unrecognized members:

- `darkboxDelta`: the string `1.0.0`.
- `base`, `target`: objects with exactly `packageId`, `manifestSha256` and
  `inventorySha256`, identifying the corresponding complete edition.
- `targetFiles`: all target regular files, sorted by bytewise ASCII path, each
  with exactly `path`, `size` and `sha256` as in section 14. This list includes
  manifest.json, canonical files and detached signatures. Paths are unique,
  case-unambiguous and valid under the common rules.
- `folders`: every target manifest folder path, sorted by bytewise ASCII path,
  without duplicates, including empty directories.
- `changed`: target paths whose size or SHA-256 differs from the base, or which
  are absent from the base, sorted by bytewise ASCII path, without duplicates.
  `files/N` contains the complete raw target file for `changed[N]`.
- `removed`: base file paths absent from the target, sorted by bytewise ASCII
  path, without duplicates. Replacements are represented by `changed`.

Each edition identity hashes the exact manifest bytes with SHA-256. Its
`inventorySha256` hashes a canonical logical file inventory: build an array of
all regular files sorted by bytewise ASCII path, with each object serialized in
key order `path`, `size`, `sha256`. Serialize compact UTF-8 JSON without whitespace,
BOM or trailing newline; sizes are ordinary base-10 integers without leading
zeroes, paths are unescaped ASCII under section 4, and hashes are lowercase hex.
Hash those exact JSON bytes with SHA-256. This binds base resources even if the
manifest is unchanged. Directory entries, timestamps and compression are excluded.
The inventory itself is not a signer authentication mechanism.

Reconstruction MUST fully verify the base, compare both base identity hashes,
validate the complete transfer and its exact changed/removed lists, and bound
both transport and reconstructed sizes using reader-owned limits. It MUST copy
unchanged files from that verified base, copy changed files from their indexed
payloads and omit removed files. It MUST then fully verify the reconstructed
target, its complete targetFiles inventory, folders and both target identity
hashes before publication. Signed targets require externally trusted signer
keys, but no new signature or private signing key. Exact signed bytes MUST survive.
A rejected link MUST leave base and existing destinations unchanged.

Chains MUST be applied in order, with each fully verified reconstructed target
serving as the next base. A missing or mismatched base blocks reconstruction;
readers MUST NOT guess or fetch one from the network. Tools SHOULD retain periodic
complete editions and bound chain depth under application policy. SQLite changes
transfer the whole database; this version does not define page patches. Deltas
reduce retained/transmitted bytes, not the full verification cost. Appended ZIP
updates with duplicate entry names remain forbidden.

## 16. Direct media access and reader storage policy

Producers SHOULD use STORE for already compressed media, including JPEG, PNG,
WebP and MP4, and SHOULD align each such entry's data start to a 4096-byte boundary
using valid local ZIP extra fields. Alignment is an optimization, not a conformance
requirement; readers MUST accept unaligned valid STORE and DEFLATE entries.
Readers MAY serve bounded byte ranges from STORE entries in a fully verified,
immutable ZIP without extracting media. Range offsets MUST use verified local
header/data boundaries, remain inside the selected entry and support ZIP64.
Protected entries expose ciphertext; range access does not bypass authentication.
Readers and applications MUST exclude concurrent mutation while direct handles
are in use. DEFLATE entries require decompression before random byte access.

Applications SHOULD select private staging storage explicitly rather than modify
process-global temporary-directory environment variables. Atomic output candidates
SHOULD remain beside the destination to support same-filesystem publication.
Reader limits are external policy and MUST NOT be increased by manifest claims,
a delta or an extension. Tools SHOULD provide named large-library presets and
actionable limit errors, while retaining bounded entry counts, metadata, total
sizes and deadlines. A limit increase never establishes conformance by itself.
