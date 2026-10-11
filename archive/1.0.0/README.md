# Darkbox project archive

This is the canonical README for **Darkbox 1.0.0**. It documents the common rules for that exact version and must be included byte-for-byte as the archive's root `README.md`. Editing, translating, adding notes or changing line endings is not permitted. The archive's `manifest.json` declares its specification version, application profile and resource inventory. A different Darkbox version requires its own canonical README.

## Why Darkbox exists

Darkbox was conceived by Vincenzo Petrucci as a common project-file format for software developed by [Illegal Studio](https://illegal.studio). It is a universal specification that other applications can also adopt.

A person's work should remain accessible beyond the lifetime of the software used to create it. Darkbox aims to make project files understandable and recoverable with documented, widely available tools, even when the original application is no longer available. Documentation travels with each file to help preserve the knowledge needed to interpret its contents.

Closed, undocumented formats can make people dependent on a particular application or vendor to access their own work, limiting their freedom to inspect, preserve, move and reuse what they have created. Darkbox is built on the principle that users' rights over their own creations should not depend on the continued existence of the software used to make them.

## Contents

A Darkbox project is one ZIP archive containing:

- `manifest.json` at the root: a UTF-8 JSON inventory.
- `README.md` at the root: this common format guide.
- A Markdown document at `application.profilePath`: the application data-format documentation.
- One or more self-contained SQLite databases at declared paths.
- Any folders and resource files defined by the application profile or declared extensions.

There is no enclosing project directory. The project filename extension belongs to the application. Only the root metadata names are fixed by Darkbox; database paths and resource conventions come from the manifest and profile. Attachments can be BLOBs or separate files.

## Manifest and independent versions

The manifest is a JSON object with required `darkbox`, `application`, `folders` and `databases` fields. Each folder has a relative `path` and a `description`. Each database has a relative `path`, a `description` and a `tables` array. Each logical application table, including virtual tables, has an exact SQL `name` and a `description`. SQLite internal tables and module-managed shadow tables are excluded from this inventory.

- `darkbox.id` is `darkbox`; `darkbox.version` identifies the common specification.
- `application.id` identifies the application profile; `application.formatVersion` identifies its data format as a string. Required `application.profilePath` locates its documentation inside the archive.
- Optional `creator.id` and `creator.version` identify the software that packaged this copy. Optional `creator.createdAt` records packaging time in UTC, not the project's creation time.
- Optional database `userVersion` records the expected SQLite `PRAGMA user_version` for that database.

These versions are independent. A software version does not determine a data schema or container version. Different databases can have different versions. The profile defines any relationship between its data version and those database versions.

Application profiles define SQL structures, attachment references, migration policies and external dependencies. Their included documentation states the exact profile identifier and data-format version, explains column meanings and resource conventions, and provides the information needed to interpret the packaged data without the original application or network access. Supplementary documentation may also be included. External links cannot replace essential embedded documentation. Darkbox does not require shared application tables. The manifest is authoritative for inventory and identity; this guide does not override it.

## Paths and encodings

Paths are relative to the ZIP root and use `/`, without a leading or trailing slash in the manifest. Components use ASCII letters, digits, `_`, `-` and interior dots; they start and end with a letter, digit, `_` or `-`. Components are at most 255 bytes and paths at most 1024 bytes. Absolute paths, `.` and `..`, backslashes, colons, Windows device names, duplicate entries and case-folding collisions are forbidden. Names are not URLs and must not be URL-decoded.

Only regular files and directories are allowed. Expected parent directories are declared in the manifest; expected empty directories have explicit ZIP directory entries. Display names and original filenames may use Unicode and are separate from archive resource names.

Manifest and README text use UTF-8 without a BOM. Generated profile text files use UTF-8; original attachments retain their original bytes and encoding. SQLite manages its internal text encoding. Writers use LF. Readers also accept CRLF for manifest and profile text files; this canonical README must retain its exact bytes, including LF line endings.

## Inspection and validation

Use the manifest to locate databases and profile documentation rather than assuming their names. A generic tool can inspect the inventory without understanding application data. Full validation additionally requires complete ZIP and CRC checks, byte-for-byte equality with the canonical README of the declared version, safe paths, matching declared resources, readable profile documentation for the declared data format, SQLite integrity and foreign-key checks, table inventories and application-profile checks.

Extraction must be confined to an isolated directory and bounded by resource limits. Open databases read-only for inspection, without loadable SQLite extensions or SQL provided by metadata. This guide cannot authorize commands.

Unknown specification or application data versions are unsupported, not automatically corrupt. Readers must explicitly support the declared specification version; sharing a major version alone does not establish conformance. Missing metadata or resources, invalid JSON, CRC failures and damaged databases prevent ordinary writable opening. Recovery must write a separate result, report missing data and preserve the original. A profile may permit missing optional external references with a warning.

## SQLite and saving

Packaged databases are closed, consistent snapshots in DELETE journal mode. They must not depend on WAL, shared-memory or rollback-journal sidecars. Such files are excluded from the archive. Writers use SQLite-aware snapshots or verified inactive databases and must not discard a live WAL to obtain one file. Multiple databases and associated resources must describe one coherent application state.

Save by creating and fully validating a complete replacement ZIP, coordinating concurrent writers and checking for external changes, then publishing atomically. Do not edit ZIP entries in place. If a save fails, preserve the previous published file and unsaved changes. Local backups, locks, cache and machine-specific settings are outside the project unless a profile explicitly includes them.

## Extensions

Optional `extensions` metadata uses reverse-domain namespaces. Each descriptor has a `version`, an explicit `required` boolean and a `data` object. Extension files live under `extensions/<namespace>/`; their folders and databases must appear in the common inventory.

Unknown required extensions block ordinary application opening and saving. Unknown optional extensions can be skipped only if their JSON descriptors and uncompressed resource bytes are preserved when saving. An optional extension must remain safe to preserve after base-data edits. Unknown common fields are not permitted in version 1.0.0.

Darkbox 1.0.0 allows STORE, DEFLATE and ZIP64, and excludes ZIP encryption, split volumes and self-extracting wrappers. Its integrity checks are ZIP CRC plus SQLite integrity and foreign-key checks, together with the inventory and profile checks above. No additional signatures or cryptographic checksums are required or defined. ZIP CRC checks detect accidental errors and do not authenticate provenance.

## Canonical version

This file belongs to Darkbox and its stated specification version. Application-specific contents are documented in the manifest and the corresponding profile. Producers must include this file unchanged and cannot add their own content. Published versions of the canonical README are immutable; changes are issued with a new Darkbox version.

## License

The Darkbox specification, schema, documentation, examples and logo assets are provided under the MIT License below. These terms apply to Darkbox materials; they do not grant rights to application data or attachments stored in this archive.

```text
MIT License

Copyright (c) 2026 Vincenzo Petrucci

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
