# Application profiles

This document explains how independently defined application profiles use Darkbox. Each archive includes the documentation for its exact application data-format version, located by `application.profilePath`. The [specification](specification.md) defines the common documentation requirements; profiles define the application's data semantics.

## Profile responsibilities

An embedded profile document must state its application identifier and data-format version and document:

- Project filename extension, database and folder paths, SQL tables, columns, indexes, triggers and required modules.
- Column meanings and structured payload fields, including encodings, units and value conventions where relevant.
- The relationship, if any, between the application data version and individual SQLite `user_version` values.
- Authoritative data, derived caches, resource IDs, file paths, media types and reference rules.
- Mandatory embedded resources versus permitted external references, including behavior when external dependencies are unavailable.
- Application-level validation, invariants and resource limits.
- Readable, writable and migratable versions, backup and recovery policies, and treatment of unknown application data.
- Optional or required extensions and which resources remain safe for opaque preservation.
- Protected SQLite columns and attachments, exact plaintext encoding/structure, NULL behavior, stable record identifiers and externally supplied key selection and trust policy when using the official protection extension.

The information needed to interpret packaged data must be available inside the archive without its original application or network access. Additional embedded documents can supplement the main profile document; external links cannot replace essential documentation. A table description in the manifest is an inventory entry, not a complete data-format definition.

Profile documentation is Markdown encoded as UTF-8 without a BOM; writers use LF. `docs/profile.md` is the recommended archive path, with `docs` declared in `folders`. Other valid paths are allowed inside declared folders, outside extension namespaces and the reserved `docs/sqlite/` and `docs/darkbox/` subtrees. The document is separate from the unchanged, version-specific Darkbox documentation bundle. Every archive includes all contents of `archive/<darkbox.version>/` in its ZIP root, including the original SQLite binary-format reference and the canonical file catalog; the application profile explains the meaning of the data stored using that format. From common 1.6.0, an archive that declares an official extension also includes the canonical bundle of that extension version, copied from `extensions/<namespace>/<version>/` into the reserved `docs/darkbox/<name>/` directory, with its folders declared in `folders`.

A version-specific validator should be accessible without running the application. Documentation does not authorize automatic execution of SQL or migrations. If a profile uses several databases or file attachments, it must specify a coherent snapshot across them. SQLite foreign-key checks on each database do not validate cross-database references.

The [official protection extension](../extensions/studio.illegal.darkbox.protection/1.0.0/docs/darkbox/protection/1.0.0.md) keeps public columns and documentation readable while encrypting selected BLOB values and individual attachments. Producers encrypt before inserting into SQLite. Introducing protected representations changes application data conventions and requires the profile owner's compatibility/version decision. Keys, license/password policy and signer trust belong to the application; generic verification authenticates bytes and context, then leaves plaintext type and meaning validation to the profile.

## Choosing durable formats

The common specification fixes the container, the manifest, the SQLite snapshots and the documentation. It does not restrict the formats of resource files or of the values stored in SQLite columns: a package is conforming whether an attachment is plain text or an undocumented binary blob. Long-term readability of the content therefore depends on the choices a profile makes. The following recommendations are guidance for profile authors, not conformance requirements.

- Store text as UTF-8 in SQLite `TEXT` columns or in plain text files. Prefer plain text (`.txt`) or Markdown (`.md`) for prose; both remain readable with any editor, without the application.
- Represent rich text with a documented, text-based markup (Markdown, HTML or a JSON structure described in the profile) instead of a serialized in-memory object or a word-processor binary format.
- Store structured values as columns where possible, or as JSON with documented fields. Avoid language-specific serialization formats, which tie the data to one runtime and often to one version of it.
- Prefer openly specified, widely implemented formats for media: PNG, JPEG or WebP for images, SVG for vector graphics, PDF for fixed-layout documents, FLAC, WAV, Opus or AAC in standard containers for audio, and common codecs in MP4, WebM or Matroska for video.
- Do not compress or encode a text value before storing it unless the profile documents the exact algorithm and parameters; the ZIP container already compresses entries.
- Record the media type of every resource whose format is not implied by the profile, so that a generic tool can identify it.

When an application-specific or proprietary format cannot be avoided, the profile must still satisfy the rule above: document its structure in the archive, precisely enough to read the data without the original application. If that is impractical, store a readable rendition next to the original (for example extracted text or a rendered image) and define which of the two is authoritative.

## Illustrative profiles

These profiles are fictional examples, not reconstructions of existing application formats. Their schemas, resource conventions and versions are not common Darkbox requirements.

| Profile | Data-format version | SQLite `user_version` | Resource model |
| --- | --- | --- | --- |
| [Notebook](../examples/profiles/notebook.md) | `"3"` | `12` | One database with embedded attachment BLOBs and an FTS5 index |
| [Canvas](../examples/profiles/canvas.md) | `"7"` | Main `4`, history `2` | Two databases and image files with explicit resource mappings |

The [example manifests](../examples/README.md) both use `application.profilePath = "docs/profile.md"`. A packager copies the corresponding profile document to that location, preserving the distinction between the two example data formats.

## Evolving a real profile

A container-only conversion can retain the existing application data version if its owner defines that number as a payload version and leaves the payload conventions unchanged. This does not imply that older software can open the new ZIP. If the application historically versions the entire project-file format, its owner must explicitly decide whether adoption requires a new data-format identifier or version.

Moving attachments from BLOBs to resource files changes application conventions even when text tables stay unchanged. Such a profile change needs an explicit version, authoritative ID-to-path mapping, migration and recovery plan. Keeping both representations requires a defined source of truth and consistency rule, not just two copies.

Existing portable-package formats, local caches, installed libraries, licenses and readable-folder exports do not become Darkbox projects automatically. A profile decides what belongs inside a project and what remains an optional external dependency. The common container never embeds external material solely because an application happens to use it locally.

When a migration changes the data-format version, package the matching profile documentation together with the migrated payload and updated manifest. The archived documentation must continue to describe the exact data being saved.

## Synchronization mappings (1.5.0 and later)

A profile adopting `studio.illegal.darkbox.sync` includes its exact immutable
`SyncMapping` and documents stable record/codec interpretation, synchronized and
local-only columns, ordered owner relationships, its deterministic conflict view
and the reserved `_darkbox_sync_` journal tables. The application registers the
exact projection adapter version. A mapping alone cannot enforce arbitrary
business invariants or authorize execution of packaged SQL/code.

Concurrent valid operations remain in causal state even when the visible database
needs to quarantine conflicting records. Profiles define deterministic projection
and fallback semantics independently of arrival order, locale or wall clock.
Data-format changes require an explicitly reconciled new sync domain in protocols
1.0.0 and 1.1.0.

Sync 1.1.0 is for common 1.6.0 and later 1.x versions; sync 1.0.0 stays bound to
common 1.5.0 exactly and is not declared by a 1.6.0 manifest. The two protocol
versions share the same mapping format and rules, and a domain never changes its
protocol version. See [the sync guide](sync.md), the
[1.1.0 normative reference](../extensions/studio.illegal.darkbox.sync/1.1.0/docs/darkbox/sync/1.1.0.md)
and, for existing 1.0.0 domains, the
[1.0.0 normative reference](../archive/1.5.0/docs/darkbox/sync/1.0.0.md).
