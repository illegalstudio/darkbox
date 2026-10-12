# Notebook application profile 3

This fictional profile is part of the Darkbox examples. It documents the exact data format identified below and can be read independently of its application.

Identifier: `org.example.notebook`. Data-format version: `"3"`. Fictional extension: `.notebook`. Layout: `data/project.sqlite`, with `data` declared as a folder. SQLite `user_version` is `12`; this mapping is explicit and independent of the data-format number.

The manifest lists four logical tables. Attachments remain BLOBs; no attachment folder is required. The following SQL defines an illustrative database for those entries:

```sql
PRAGMA user_version = 12;
CREATE TABLE project (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL
);
CREATE TABLE documents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  position INTEGER NOT NULL
);
CREATE TABLE attachments (
  id TEXT PRIMARY KEY,
  original_name TEXT NOT NULL,
  mime TEXT NOT NULL,
  bytes BLOB NOT NULL
);
CREATE VIRTUAL TABLE document_search USING fts5(
  document_id UNINDEXED, title, body
);
```

There is exactly one `project` row. Project, document and attachment IDs are stable UUID strings. Documents are ordered by `(position, id)` and their bodies contain Unicode text. A `resource:<attachment-id>` reference in a body resolves to `attachments.id`; its display filename does not identify the resource.

`document_search` is a derived index, not the source of document text. A profile-aware writer refreshes it from documents before packaging. Its FTS5 shadow tables stay inside SQLite but are omitted from the manifest table inventory. FTS5 is required for full profile validation; a generic reader can still inspect the manifest without it.

A profile validator checks the explicit version mapping, table structures, the single project identity, UUIDs, embedded references and search-index agreement. This fictional revision defines no external dependencies or data migrations. Only data-format version `"3"` is declared readable and writable here; other versions require another profile definition. The common specification supplies the snapshot and publication rules.

## Column meanings and value conventions

UUID values use lowercase hexadecimal in the standard `8-4-4-4-12` hyphenated form. Every ID is non-null, and references compare the complete string. Display names and text are Unicode data; they are not archive paths.

| Column | Meaning |
| --- | --- |
| `project.id` | Stable identity of this project |
| `project.title` | Project display title |
| `documents.id` | Stable document identity |
| `documents.title` | Document display title |
| `documents.body` | Plain text with embedded attachment references |
| `documents.position` | Integer ordering key, sorted ascending and then by `id` |
| `attachments.id` | Stable attachment identity |
| `attachments.original_name` | Original display filename, never used to locate bytes |
| `attachments.mime` | Media type describing the attachment bytes |
| `attachments.bytes` | Complete authoritative attachment bytes |
| `document_search.document_id` | ID of the indexed document |
| `document_search.title`, `document_search.body` | Derived copies of the document text for search |

A body reference is the literal prefix `resource:` followed immediately by the attachment UUID. It resolves within this database, and every such reference must identify an existing attachment. Empty titles and bodies are permitted; attachment filenames and media types are nonblank strings. Zero-length attachment bytes are permitted.

The search index has one logical row per document with the same ID, title and body. Search rows and FTS5 shadow tables can be rebuilt from `documents`; project rows, document rows and attachment bytes are authoritative. There are no cross-database relationships or external file resources in this revision.

A validator checks the required schema and column meanings, non-null UUIDs, the single project row, attachment references, nonblank attachment metadata and search-index agreement in addition to Darkbox container checks.

There are no additional application-defined indexes or triggers and no profile-specific size or count limits; reader resource limits still apply. Unknown tables, columns or data conventions require a separately documented profile version before writable use. Recovery preserves the original archive and writes a separate result under the common Darkbox rules.

This document is Darkbox example documentation covered by the MIT License reproduced in the archive's Darkbox README.
