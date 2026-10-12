# SQLite reference documentation

This directory contains the original SQLite database-file-format documentation and its presentation assets, captured from the official SQLite website for Darkbox 1.0.0. The upstream files are reproduced byte-for-byte, without translation, rewriting or conversion to another document format.

- Capture time: 2026-10-12T10:07:35Z
- File-format article's stated last update: 2025-12-25 10:33:36Z
- Scope: SQLite's on-disk format, documented for SQLite releases since 3.0.0. This is not the version of the SQLite software that created any packaged database.

| Included file | Original source |
| --- | --- |
| [fileformat2.html](fileformat2.html) | [SQLite original](https://www.sqlite.org/fileformat2.html) |
| [copyright.html](copyright.html) | [SQLite original](https://www.sqlite.org/copyright.html) |
| [sqlite.css](sqlite.css) | [SQLite original](https://www.sqlite.org/sqlite.css) |
| [images/sqlite370_banner.svg](images/sqlite370_banner.svg) | [SQLite original](https://www.sqlite.org/images/sqlite370_banner.svg) |
| [images/nocopy.gif](images/nocopy.gif) | [SQLite original](https://www.sqlite.org/images/nocopy.gif) |

## Reading offline

Open `fileformat2.html` with a local HTML viewer. Its complete text, tables and internal section links are included. The stylesheet and images are local, and the article remains readable without JavaScript or network access. `copyright.html` records the upstream public-domain dedication.

Links to other SQLite pages are preserved as they appear in the original HTML. Those other pages are not part of this bundle; use the original source URL above to consult them online. They do not replace the included file-format article. SQLite's descriptions of journals and WAL are preserved as part of the original documentation; Darkbox's packaging rules still forbid including those sidecars.

## Distribution

This directory is part of the canonical `archive/1.0.0/` bundle. Copy all contents of that version directory into every Darkbox 1.0.0 archive's ZIP root, preserving relative paths and every file's bytes; these SQLite materials therefore appear under `docs/sqlite/`. Do not include an enclosing `archive/` or version directory. Do not refresh individual files from the live website when writing a project: the Darkbox version selects this captured bundle. Published Darkbox bundles are immutable.

The SQLite code and documentation have been dedicated to the public domain by their authors, as stated in the original `copyright.html`. These third-party materials retain their upstream terms and are separate from the copyright and MIT License covering Darkbox-authored materials. This provenance note is Darkbox-authored documentation.
