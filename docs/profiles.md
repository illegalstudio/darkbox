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

The information needed to interpret packaged data must be available inside the archive without its original application or network access. Additional embedded documents can supplement the main profile document; external links cannot replace essential documentation. A table description in the manifest is an inventory entry, not a complete data-format definition.

Profile documentation is Markdown encoded as UTF-8 without a BOM; writers use LF. `docs/profile.md` is the recommended archive path, with `docs` declared in `folders`. Other valid paths are allowed inside declared folders, outside extension namespaces. The document is separate from the unchanged, version-specific Darkbox README.

A version-specific validator should be accessible without running the application. Documentation does not authorize automatic execution of SQL or migrations. If a profile uses several databases or file attachments, it must specify a coherent snapshot across them. SQLite foreign-key checks on each database do not validate cross-database references.

## Illustrative profiles

These profiles are fictional examples, not reconstructions of existing application formats. Their schemas, resource conventions and versions are not common Darkbox requirements.

| Profile | Data-format version | SQLite versions | Resource model |
| --- | --- | --- | --- |
| [Notebook](../examples/profiles/notebook.md) | `"3"` | `12` | One database with embedded attachment BLOBs and an FTS5 index |
| [Canvas](../examples/profiles/canvas.md) | `"7"` | Main `4`, history `2` | Two databases and image files with explicit resource mappings |

The [example manifests](../examples/README.md) both use `application.profilePath = "docs/profile.md"`. A packager copies the corresponding profile document to that location, preserving the distinction between the two example data formats.

## Evolving a real profile

A container-only conversion can retain the existing application data version if its owner defines that number as a payload version and leaves the payload conventions unchanged. This does not imply that older software can open the new ZIP. If the application historically versions the entire project-file format, its owner must explicitly decide whether adoption requires a new data-format identifier or version.

Moving attachments from BLOBs to resource files changes application conventions even when text tables stay unchanged. Such a profile change needs an explicit version, authoritative ID-to-path mapping, migration and recovery plan. Keeping both representations requires a defined source of truth and consistency rule, not just two copies.

Existing portable-package formats, local caches, installed libraries, licenses and readable-folder exports do not become Darkbox projects automatically. A profile decides what belongs inside a project and what remains an optional external dependency. The common container never embeds external material solely because an application happens to use it locally.

When a migration changes the data-format version, package the matching profile documentation together with the migrated payload and updated manifest. The archived documentation must continue to describe the exact data being saved.
