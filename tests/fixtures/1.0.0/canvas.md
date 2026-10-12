# Canvas application profile 7

This fictional profile is part of the Darkbox examples. It documents the exact data format identified below and can be read independently of its application.

Identifier: `org.example.canvas`. Data-format version: `"7"`. Fictional extension: `.canvas`. The manifest declares two databases and an image folder:

```text
data/project.sqlite       # SQLite user_version 4
data/history.sqlite       # SQLite user_version 2
media/images/             # declared along with parent media
```

The main database contains a JSON project document and a resource-path mapping:

```sql
PRAGMA user_version = 4;
CREATE TABLE project (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  document TEXT NOT NULL
);
CREATE TABLE resources (
  id TEXT PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  original_name TEXT NOT NULL,
  mime TEXT NOT NULL
);
```

The history database records immutable documents:

```sql
PRAGMA user_version = 2;
CREATE TABLE revisions (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  document TEXT NOT NULL
);
```

There is exactly one main `project` row. Each current or retained JSON document has a numeric `version = 7`, stable UUID `id`, nonblank `name`, finite viewport coordinates with a positive scale, and an ordered `items` array. An image item has a unique UUID `id`, `kind = "image"`, a UUID `resourceId`, finite coordinates and rotation, and positive width and height. Later array entries draw above earlier ones. These payload details are profile rules, not common manifest fields.

Every image reference in the current document and retained revisions resolves to `resources.id` in the main database. The mapping's `path` is archive-relative and has the form `media/images/<resource UUID>.png`, `.jpg` or `.webp`, consistent with `mime`. UUID filenames preserve identity independently of Unicode `original_name`. File bytes are authoritative; the example defines no duplicate BLOB copy. Unused resources can be removed only when no current document or retained revision references them.

`revisions.id` is a stable UUID; `created_at` is an RFC 3339 UTC timestamp. Each saved revision document follows version 7 rules and keeps the same project identity. The two databases and image files must be captured together so history cannot refer to missing resources.

A profile validator checks both explicit database versions, SQL structures, document versions, identities, item geometry, image type and references across both databases and files. The optional `org.example.presentation` extension stores only an accent color; its descriptor is safe to preserve after base-project edits and does not require resource folders. This fictional revision declares only version `"7"` readable and writable and defines no migration or external dependency.

## Column meanings and value conventions

UUID values use lowercase hexadecimal in the standard `8-4-4-4-12` hyphenated form. Every UUID is non-null, and references compare the complete string.

| Column | Meaning |
| --- | --- |
| Main `project.id` | Singleton SQL row key, always integer `1`; the project UUID is in its JSON document |
| Main `project.document` | Authoritative current project document as strict JSON text |
| Main `resources.id` | Stable identity of an image resource |
| Main `resources.path` | Exact archive-relative path to authoritative image bytes |
| Main `resources.original_name` | Original display filename, independent of the resource path |
| Main `resources.mime` | Image media type, consistent with the file bytes and suffix |
| History `revisions.id` | Stable identity of a retained revision |
| History `revisions.created_at` | Revision save time as an RFC 3339 UTC timestamp ending in `Z` |
| History `revisions.document` | Immutable project snapshot as strict JSON text |

Strict JSON has no duplicate object keys or non-JSON numbers. Both JSON document columns use this structure:

```json
{
  "version": 7,
  "id": "f236e209-2cbb-46a0-88d9-6187c5ee573e",
  "name": "Example canvas",
  "viewport": { "x": 0, "y": 0, "scale": 1 },
  "items": [
    {
      "id": "67e55934-0ef2-42c7-97de-cfdbe498a67c",
      "kind": "image",
      "resourceId": "df12528a-1cb4-48c7-9b17-e084f3c5368c",
      "x": 0,
      "y": 0,
      "rotation": 0,
      "width": 100,
      "height": 100
    }
  ]
}
```

All shown fields are required; `items` may be empty. This revision defines image items only. Project names are nonblank Unicode strings. The viewport's `x` and `y` identify the canvas coordinate displayed at the top-left, and `scale` gives display pixels per canvas unit. Item `x` and `y` place its unrotated top-left corner in canvas units; width and height are positive canvas-unit lengths. Coordinates increase rightward and downward. Rotation is clockwise in degrees around the item's center. Geometry values are finite numbers, and viewport scale is positive.

Item IDs are unique within each document. Project IDs agree across the current document and all retained revisions. Each image `resourceId` resolves to the main database's resource mapping, including when the reference appears only in retained history.

Resources use `image/png` with `.png`, `image/jpeg` with `.jpg`, or `image/webp` with `.webp`. Their paths use the exact UUID from `resources.id`. Original names are nonblank Unicode strings. Image bytes must be readable as the declared media type. Unreferenced mappings are permitted; removal must follow the history-aware rule above.

The current document, retained revisions and resource files are authoritative. This revision defines no derived cache, external dependency or executable migration. A validator checks these field meanings and relationships in addition to the SQL structure, explicit version mappings, Darkbox container checks and optional presentation-extension descriptor.

There are no additional application-defined indexes or triggers, required SQLite modules or profile-specific size or count limits; reader resource limits still apply. Unknown SQL structures, document fields or item kinds require a separately documented profile version before writable use. Recovery preserves the original archive and writes a separate result under the common Darkbox rules.

This document is Darkbox example documentation covered by the MIT License reproduced in the archive's Darkbox README.
