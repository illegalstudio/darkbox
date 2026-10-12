# Darkbox 1.0.0

Specification identifier: `darkbox`. Date: 2026-10-12.

The authoritative versioned copy is `specification/1.0.0.md` in the Darkbox source distribution; `docs/specification.md` is a convenience copy of the current specification.

**MUST**, **MUST NOT**, **SHOULD** and **MAY** indicate a requirement, prohibition, recommendation and option within this specification.

## 1. Scope and independent versions

Darkbox defines a universal project container and its metadata. An application profile defines database schemas, resource references, external dependencies and data migrations. Darkbox imposes no shared application tables or attachment model.

| Manifest field | Meaning | Fictional example |
| --- | --- | --- |
| `darkbox.id` | Stable common specification identifier | `darkbox` |
| `darkbox.version` | Version of the container and metadata rules | `1.0.0` |
| `application.id` | Stable application profile identifier | `org.example.notebook` |
| `application.formatVersion` | Profile-specific data-format version | `"3"` |
| `application.profilePath` | Archive-relative path to the included profile documentation | `docs/profile.md` |
| `creator.id`, `creator.version` | Optional software that packaged this copy | `org.example.packager`, `"2.5.0"` |
| `databases[].userVersion` | Optional expected SQLite `PRAGMA user_version` of that database | `3` |

Versions from different domains MUST NOT be compared. `application.formatVersion` is interpreted only by its profile; it need not use SemVer. Multiple databases can have different SQLite `user_version` values. A profile can explicitly map its data version to a database version, but Darkbox does not infer that mapping. Creator software is provenance, not a compatibility requirement or proof of application support.

The application keeps its own project filename extension. The common specification does not assign an extension or require one universal extension.

## 2. ZIP structure

A Darkbox file MUST be one complete ZIP archive with a readable central directory. ZIP encryption, split volumes and self-extracting wrappers are forbidden. STORE and DEFLATE compression methods are allowed; ZIP64 is allowed. Entry ordering, ZIP timestamps and stored permissions have no application meaning. CRC checks remain mandatory regardless of compression.

These regular files MUST exist at the root, with exactly these names:

```text
manifest.json
README.md
```

Every archive MUST also include the entire canonical documentation bundle for its declared version: all contents of `archive/<darkbox.version>/` are copied into the ZIP root, retaining relative paths and file bytes. This directory is a source distribution location, not an enclosing directory inside the ZIP. The bundle includes the root README and the original SQLite reference documentation described in section 5.

There MUST be at least one declared, self-contained SQLite database. Database names and paths belong to the profile; `data/project.sqlite` is a recommended convention, not a common requirement:

```text
example.project
├── manifest.json
├── README.md
├── docs/
│   ├── profile.md
│   ├── darkbox/bundle.json
│   └── sqlite/            # complete canonical SQLite reference bundle
├── data/
│   └── project.sqlite
└── media/                 # only if declared by the profile
    └── image-001.png
```

There is no enclosing project directory. `folders` MUST list every expected directory, including ancestors of nested paths and all canonical bundle directories. Version 1.0.0 therefore requires `docs`, `docs/darkbox`, `docs/sqlite` and `docs/sqlite/images` in this inventory. A nonempty directory exists through its child entries; an expected empty directory MUST have a ZIP directory entry ending in `/`. Manifest directory paths do not end in `/`. An explicit directory entry cannot substitute for a regular file. Application profile documentation MUST also be inside declared folders; databases MAY still be at the root.

Regular files at the root MUST be either the required metadata files or declared databases. Declared directories are also allowed at the root. Other regular files, including application profile documentation, MUST be inside declared folders and follow a profile or extension convention. Every standalone SQLite database, including extension databases, MUST be inventoried, regardless of its filename suffix. A file with the SQLite database header is a database for this purpose; a SQLite BLOB inside another database is not a standalone archive entry.

Darkbox does not assign implicit meanings to folder names such as `assets`, `media` or `attachments`. No attachment folder is required when the profile stores attachments as BLOBs. Profiles MUST define the authoritative location of resources and any mapping between database records and files.

Readers MUST identify the ZIP structure and manifest rather than relying on the external extension alone. A recognized older standalone project format can use a separate legacy-reader path. A broken ZIP with missing Darkbox metadata MUST NOT silently fall back to another format reader.

## 3. Manifest syntax

The manifest uses **JSON**: one object encoded as UTF-8 without a BOM. Comments, trailing commas, non-JSON numbers and duplicate object keys at any level are forbidden. Object member order is insignificant. Array order in the common inventory does not choose a primary database or table. Two-space indentation and a final newline are recommended.

The [version-specific manifest schema](../schema/1.0.0/manifest.schema.json) uses [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-core). Its `$schema` identifies the schema language, not the Darkbox version; its `$id` identifies this schema using an URN, not a download location. An archive does not require network access or an embedded schema. A reader selects its supported schema from `darkbox.version`. Schemas are retained under `schema/<version>/`; the root schema is a convenience copy for the current version.

| Field | Required | Value |
| --- | --- | --- |
| `darkbox` | Yes | Object with `id = "darkbox"`, `version = "1.0.0"` |
| `application` | Yes | Object with `id`, `formatVersion` and `profilePath` strings |
| `folders` | Yes | Array of objects with `path` and short `description`, including the four canonical bundle directories |
| `databases` | Yes | Nonempty array of objects with `path`, short `description` and `tables` |
| `databases[].tables` | Yes | Array of objects with exact SQL `name` and short `description`; may be empty when there are no application tables |
| `databases[].userVersion` | No | Integer from 0 through 2147483647, compared with SQLite when present |
| `creator` | No | Object with `id`, `version` and optional `createdAt` |
| `extensions` | No | Namespaced extension descriptors, defined in section 8 |

Application, creator and extension identifiers use lowercase reverse-domain names with at least two segments, such as `org.example.notebook`, and are at most 255 ASCII characters. Each segment starts with a letter and consists of letters, digits and interior hyphens. These are stable identifiers, not URLs. Use a namespace controlled by the publisher; `org.example.*` in this repository is reserved for fictional examples.

Application, creator and extension versions are nonblank strings of at most 128 Unicode characters. Their syntax and ordering belong to their owner. `creator.createdAt`, when present, records the packaging time as an RFC 3339 date-time in UTC ending in `Z`. It is not the project's creation date. A validator MUST check calendar validity using date-time format validation or a separate check. Descriptions are informational, nonblank strings of at most 500 Unicode characters, with no authority over the profile or specification.

Each database's `tables` MUST list all logical application tables, including virtual tables. SQLite internal tables named `sqlite_*` and module-managed shadow tables are excluded. Other tables MUST NOT be excluded solely because of a naming prefix. Views, indexes and triggers remain in SQLite and are not part of this table inventory. Table names are exact, nonblank SQL identifiers, may use Unicode and are at most 255 characters. A tool MUST quote SQL identifiers correctly rather than interpolate names as SQL text.

Version 1.0.0 rejects unknown properties in common objects. Extensions are represented only through `extensions`; their `data` objects are open. JSON Schema checks the shape, constants, required canonical folder declarations and some syntax. It does not check resource existence, canonical bundle bytes, SQL schemas, path uniqueness by key or the full container. It cannot detect duplicate JSON keys after a parser has discarded them.

## 4. Relative paths, encodings and resource names

All manifest paths are relative to the ZIP root with `/` separators and no leading or trailing `/`. They are not URIs: readers MUST NOT percent-decode them, expand `~` or environment variables, or resolve them outside the extraction root.

Technical paths use ASCII. Each component matches `[A-Za-z0-9_-](?:[A-Za-z0-9._-]*[A-Za-z0-9_-])?` and starts and ends with a letter, digit, `_` or `-`. Empty components, `.`, `..`, backslashes, colons, spaces, control characters and trailing dots are forbidden. Paths are limited to 255 bytes per component and 1024 bytes per complete path. Windows device names are forbidden case-insensitively, also before a filename extension: `CON`, `PRN`, `AUX`, `NUL`, `COM1` through `COM9` and `LPT1` through `LPT9`.

ZIP entry names follow the same rules, allowing a final `/` only for a directory. Names use UTF-8; ASCII avoids dependence on legacy ZIP codepages. Exact paths are authoritative, but the archive MUST also avoid collisions after ASCII case folding, including implicit parent directories. Thus `media/A.png` and `media/a.png` cannot coexist, nor can `Data/a.png` and `data/b.png`. Duplicate entries, file/directory collisions, symbolic links and other special filesystem entries are forbidden. The root metadata names are reserved, including their case-folded equivalents.

All canonical bundle file paths are reserved, including their case-folded equivalents. The `docs/sqlite/` and `docs/darkbox/` subtrees are reserved in their entirety and MUST contain only their canonical files and directories. Profiles and extensions MUST NOT add or replace resources there. The shared `docs/` directory MAY contain application documentation at other paths, such as `docs/profile.md`.

Folder paths and database paths MUST be unique within their inventories and cannot denote the same location. Table names within a database MUST be unique according to SQLite's ASCII case-insensitive identifier comparison. A database's parent folders MUST be declared, except for a root database.

The manifest, included README and generated text files governed by a profile MUST use UTF-8 without a BOM. Writers use LF; readers also accept CRLF for the manifest and profile text files. Canonical bundle files retain their exact bytes, including the README's LF line endings and the captured upstream documentation's original encoding, as required by section 5. SQLite handles its internal text encoding: Darkbox does not require rewriting an otherwise valid UTF-16 database. Original attachments retain their original bytes and encoding; profiles define how they are interpreted.

Display names and original attachment filenames are data, not ZIP paths, and may use arbitrary Unicode. A profile that stores resource files SHOULD use stable technical names, such as UUIDs or hashes, with an explicit mapping to display names. Database IDs containing characters forbidden in paths MUST NOT become filenames through an implicit transformation.

## 5. Included documentation and declared versions

### Canonical documentation bundle

The complete contents of `archive/<darkbox.version>/` are the canonical documentation bundle for that specification version. For `darkbox.version = "1.0.0"`, a writer MUST copy every file and directory from [archive/1.0.0/](../archive/1.0.0/) into the ZIP root, preserving relative paths and file bytes. The source directory itself is not copied as an enclosing directory. The manifest, application profile documentation, databases and other resources are added separately at their declared paths.

The canonical files for version 1.0.0 are:

| Archive path | Purpose |
| --- | --- |
| `README.md` | Canonical Darkbox guide and full MIT notice for Darkbox materials |
| `docs/darkbox/bundle.json` | Canonical file and directory catalog with SHA-256 reference digests |
| `docs/sqlite/fileformat2.html` | Original SQLite on-disk database-format reference |
| `docs/sqlite/copyright.html` | Original SQLite public-domain notice |
| `docs/sqlite/sqlite.css` | Original local stylesheet for the captured HTML pages |
| `docs/sqlite/images/sqlite370_banner.svg` | Original SQLite banner used by the captured pages |
| `docs/sqlite/images/nocopy.gif` | Original image used by the copyright page |
| `docs/sqlite/SOURCE.md` | Source URLs, capture provenance, offline-reading and distribution notes |

Writers MUST NOT edit, translate, prepend or append content, change line endings or encodings, omit files, or add producer or application notes to any canonical file. Preservation applies to the uncompressed file bytes and paths; ZIP compression, entry order and timestamps need not match a source distribution. A writer MUST select the bundle for the declared specification version, rather than automatically using the newest bundle or downloading current upstream documentation.

The canonical README uses English, UTF-8 without a BOM and LF line endings, and states the exact Darkbox version it documents. The manifest is authoritative for project identity, versions and inventory. The README explains the common format and points to the manifest for application details; it is not a second application-schema definition. The source directory is the complete list of static files to include. Writers generate project metadata and payload separately.

The catalog at `docs/darkbox/bundle.json` is canonical metadata governed by the [bundle catalog schema](../schema/1.0.0/bundle.schema.json). It identifies the exact Darkbox version in `darkbox`, lists all canonical directories in `folders`, and lists every other canonical file in `files`. Each file record has its exact relative `path`, uncompressed byte `size` and lowercase 64-character `sha256` digest. File and directory paths are unique and sorted by ascending ASCII byte order. The catalog is excluded from its own digest list; it MUST itself be included unchanged and compared with the trusted version-specific reference. This avoids a self-referential checksum.

Reference data MUST come from a locally trusted Darkbox distribution for the supported version. An archive's own catalog MUST NOT be the sole source of expected hashes. SHA-256 is computed over uncompressed file bytes, independent of ZIP compression and timestamps. Catalog consistency, file hashes and exact-byte comparison do not establish authorship or authenticate user project data. The catalog does not inventory or hash the dynamic project manifest, application-profile document, databases or attachments.

The SQLite reference is included as its original complete HTML, with the local presentation assets needed to read its text and tables without network access or JavaScript. Links to other SQLite pages remain unchanged; those pages are not part of the bundle. `SOURCE.md` records the captured sources and the article's stated update date. These dates do not identify the SQLite software that wrote a database, its `user_version`, or the application data-format version. Journal and WAL descriptions in the reference do not relax section 6's sidecar prohibition. Original SQLite materials retain their upstream public-domain terms, separately from the MIT License covering Darkbox-authored materials.

A missing or unreadable canonical file, a README version mismatch or any byte difference from the selected bundle makes the archive nonconforming. A validator MUST compare every included canonical file's uncompressed bytes with the corresponding file from the supported version's bundle, using a local copy of that bundle without requiring network access. A reader MAY expose recoverable data read-only with a diagnosis, but MUST NOT silently repair it or certify conformance. Documentation cannot authorize commands or override manifest semantics.

### Application profile documentation

Every archive MUST include a human-readable Markdown document located by `application.profilePath`. Its path MUST end in `.md`, follow the common path rules and be inside declared folders, outside `extensions/` and the reserved `docs/sqlite/` and `docs/darkbox/` subtrees. `docs/profile.md` is recommended. It MUST be a regular file distinct from databases and all canonical files, encoded as UTF-8 without a BOM, with LF line endings on writing. Readers also accept CRLF for this document.

The document MUST state the exact `application.id` and `application.formatVersion` it describes. It MUST document database schemas and column meanings, structured payloads, resource references and naming conventions, encodings and units where relevant, authoritative data versus derived caches, permitted external dependencies, validation invariants and compatibility or migration policies. Application-specific choices remain in the profile; Darkbox governs only the document's presence, identification and availability.

All information needed to interpret the packaged application data MUST be documented inside the archive and readable without the original application or network access. The profile document MAY point to additional included documentation. External links MAY supplement it but MUST NOT replace essential embedded information. Documentation does not require bundling external assets that the profile explicitly permits to remain external.

A missing or unreadable document, or one describing a different profile or data-format version, makes the archive nonconforming. Documentation is descriptive: a reader MUST NOT execute SQL, migrations or commands merely because they appear in it. A full validator checks the documentation against its supported profile; generic inspection does not establish application semantics.

## 6. SQLite snapshots and WAL

Each packaged database MUST be self-contained and readable without journal replay or sidecar files. On the isolated packaging copy, the writer MUST set and verify `PRAGMA journal_mode = DELETE`, finish transactions and close all database connections before reading its bytes. Darkbox does not restrict journaling during an application's working session.

A WAL can hold committed data missing from the main database file. Copying only that main file can therefore lose data; see the [SQLite WAL documentation](https://www.sqlite.org/wal.html#the_wal_file). A writer MUST NOT delete a live WAL manually to produce a single-file database.

Recommended packaging procedure:

1. Flush pending application saves and prevent database and associated-file changes throughout snapshot capture.
2. Use the [SQLite Online Backup API](https://www.sqlite.org/backup.html) for each database to create a private staging copy, including committed state represented by a WAL. Handle errors, `BUSY` and timeouts; an incomplete backup is not a packageable snapshot.
3. On the isolated destination, finish SQLite operations, set and verify DELETE journal mode, run `PRAGMA integrity_check` (all returned results must be `ok`) and `PRAGMA foreign_key_check` (no returned rows), and close all connections.
4. Verify the staging database has no required sidecars. Package only the autonomous database. SQLite `-wal`, `-shm`, rollback `-journal` and super-journal files MUST NOT be included as archive entries.

An alternative is a byte copy of a verified inactive, fully closed database after SQLite has completed any recovery and checkpointing. If checkpointing is part of capture, verify completion and prevent new writes until closure; a checkpoint without an error is not necessarily complete. Never discard sidecars to make a damaged or incomplete snapshot appear valid.

A backup of one database does not establish a global transaction across several databases and resource folders. The writer MUST capture one coherent application revision using suspended writes or an equivalent snapshot protocol. Profiles define cross-resource relationships. A valid database alone does not prove all referenced files are present.

## 7. Reading, validation and saving

### Reading and full validation

A reader MUST inspect without modifying the original. Before extraction it validates entry names, duplicates, case collisions, entry types and confinement to a private directory. It applies bounded compressed and uncompressed sizes, entry counts, memory and processing time, checking actual bytes read as well as ZIP headers. Numeric resource limits are reader or profile policies; a limit failure is distinct from corruption or an unsupported version.

A full validator MUST check:

1. Complete ZIP structure, supported compression, successful decompression and CRC for every entry.
2. Required metadata files, UTF-8 and strict JSON including duplicate-key detection, specification identity and supported version.
3. The corresponding manifest schema, path rules, inventory, official catalog, canonical file sizes and SHA-256 digests, and byte-for-byte equality with every file in the canonical bundle for the declared specification version; no additional files or directories in the reserved documentation subtrees.
4. Presence and type of every declared folder and database, declared parent folders, readable profile documentation at `application.profilePath`, no uninventoried standalone databases and no SQLite sidecars.
5. Extracted SQLite databases opened read-only, without loadable extensions or SQL supplied by metadata; integrity, foreign keys, logical table inventory and declared `userVersion`. No trial writes or trigger execution. An unavailable required SQLite module is an unsupported-capability diagnosis, not proof of corruption.
6. Application-profile requirements: supported data version, matching embedded documentation, SQL structure, application invariants, reference resolution, required resources and required extensions.

A generic tool MAY inventory metadata without implementing a profile. It MUST distinguish that from full application validation. Manifest validation, CRC success and database integrity each cover only one layer.

The Darkbox CLI's `verify` command reports machine-checkable common rules separately from application validation. Presence and text encoding of an application-profile document do not prove the accuracy or completeness of its contents. A successful common-check report MUST NOT be presented as full application conformance. `inspect` exposes metadata and diagnostics without certifying conformance. The CLI software version is independent of every specification version it supports.

A truncated ZIP, CRC failure, malformed manifest, missing declared resource or corrupt database prevents ordinary writable opening. The original MUST remain unchanged. Recovery MAY write verified data to a new destination, reporting what is missing; it MUST NOT overwrite the source or certify a partial result as valid. Missing optional external references explicitly permitted by a profile are warnings, not container corruption.

### Saving

A writer MUST create a complete replacement ZIP, never update entries in the opened archive in place:

1. Flush pending changes and capture coherent database and resource snapshots as specified in section 6.
2. Copy the complete matching canonical bundle into the archive root and prepare application profile documentation for the packaged data-format version, the updated manifest and all preserved resources, including unknown optional-extension resources. Never refresh individual canonical files from the live website.
3. Create and close a temporary ZIP in the destination directory, then fully validate the candidate before publication.
4. Coordinate concurrent writers and check that the opened source has not changed, using a shared writer lock and a reliable source identity such as a complete hash. A pre-rename check without writer coordination leaves a race. A conflict MUST preserve the source and lead to a separate-copy workflow.
5. Sync the candidate file, atomically replace the destination using the platform's supported primitives, and sync the parent directory where supported. For a new file, publish without overwriting an existing file. If the filesystem cannot meet the required guarantee, fail or save a separate copy rather than silently weaken it.

Writing, validation, capacity or conflict failures MUST leave the previous published archive intact and keep unsaved application changes available. Temporary incomplete files are not valid projects. Local backups, locks, cache and machine-specific settings are not project content unless explicitly defined by a profile.

Migrations operate on working copies after version recognition and preservation of the original. Generic inspection does not migrate data. The manifest and included profile documentation change together with the successfully migrated payload, never ahead of it. Application adoption, legacy import and migration implementations are outside this specification's scope.

## 8. Version compatibility and extensions

### Specification versions

The common version uses `major.minor.patch`, without a prerelease suffix. Readers MUST recognize and explicitly support the declared specification version. Until a version is published, its specification and canonical bundle may be revised. Once a specification version is published, its rules and entire canonical bundle are immutable; a normative change or a change to any canonical file requires a distinct version and matching bundle. This includes refreshing the captured SQLite documentation or its presentation assets. Published `archive/<version>/` directories MUST be retained unchanged.

Patch changes clarify existing rules without changing allowed structures or requirements; minor changes add optional structures without changing existing meaning; major changes introduce incompatibility or new mandatory requirements. Sharing a major version does not establish conformance: an older exact-version schema cannot certify a later version just because familiar fields are present.

| Condition | Required handling |
| --- | --- |
| Unknown common specification identifier | Reject application opening; generic ZIP inventory may remain available |
| Unimplemented common version | Report unsupported version, preserve source; only generic inspection or an explicitly uncertified read-only view |
| Unknown common field under version 1.0.0 | Report schema nonconformance rather than silently ignore it |
| Unknown application or application data version | Generic inspection allowed; no application-data modification without a supported profile or migration |
| Unknown required extension or unsupported extension version | Block ordinary application opening and saving; generic inventory allowed |
| Unknown optional extension or unsupported extension version | Skip the feature but preserve its descriptor and resources, or refuse saving if preservation cannot be guaranteed |

A profile defines its own readable, writable and migratable versions. A reader MUST NOT infer application compatibility from creator software version, ZIP extension or a database version alone.

### Namespaced extensions

An extension MUST NOT reinterpret common fields. Each member of `extensions` has a reverse-domain namespace and a descriptor with `version`, explicit boolean `required` and an object `data`:

```json
{
  "extensions": {
    "org.example.analysis": {
      "version": "1",
      "required": false,
      "data": { "summaryPath": "extensions/org.example.analysis/summary.json" }
    }
  }
}
```

This is a fragment to insert into a complete manifest. If files exist, the common inventory MUST declare both `extensions` and `extensions/org.example.analysis`. Extension files MUST be under `extensions/<namespace>/`; its databases MUST also appear in `databases`. Path-valued extension data follows the common path rules, and the extension specification defines its meaning. An extension cannot replace canonical files, write into the reserved `docs/sqlite/` or `docs/darkbox/` subtrees or replace another namespace's resources.

Namespace ownership and version interpretation belong to the extension publisher. `required = false` promises the base project remains interpretable and editable without the feature and opaque preservation remains safe after base-data edits. An extension that changes data meaning or requires synchronization with base data MUST be required.

An unaware writer MUST preserve an optional extension descriptor as a JSON value and its uncompressed resource bytes. It need not preserve JSON whitespace, ZIP compression or timestamps. It must also preserve other declared resources it cannot regenerate. If preservation is impossible, it MUST NOT overwrite the source. Permanent changes to application data conventions belong to a new profile data version, not arbitrary common fields.

Integrity validation uses ZIP CRC and the SQLite checks in sections 6 and 7. The canonical catalog additionally uses SHA-256 for comparison with official static documentation. This version defines no cryptographic digest inventory of user project data, signatures, application encryption or public extension registry. ZIP CRC detects accidental errors, not authenticity. Any future addition requires an explicit specification rather than a convention inferred from a filename.
