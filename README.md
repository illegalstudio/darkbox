<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-light.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo-dark.svg">
    <img src="assets/logo-dark.svg" alt="Darkbox logo" width="160" height="160">
  </picture>
</p>

<h1 align="center">Darkbox</h1>

<p align="center">
  <em>The post-apocalyptic file format.</em>
</p>

<p align="center">
  <a href="docs/specification.md"><img src="https://img.shields.io/badge/specification-1.0.0-303A46?style=flat-square&amp;color=303A46" alt="Specification 1.0.0"></a>
  <a href="schema/manifest.schema.json"><img src="https://img.shields.io/static/v1?label=JSON%20Schema&amp;message=2020-12&amp;color=303A46&amp;style=flat-square" alt="JSON Schema 2020-12"></a>
</p>

<p align="center">
  <strong>ZIP container &middot; SQLite databases &middot; JSON manifest &middot; Included documentation</strong>
</p>

<p align="center">
  A universal specification for project files, designed to keep your work understandable and accessible even when the application that created it is no longer available.
</p>

<p align="center">
  <a href="https://illegal.studio/en/products/darkbox"><strong>Darkbox on illegal.studio</strong></a>
</p>

---

The common specification governs packaging and metadata. Application profiles define their own database schemas, resource conventions, data versions and migrations. Applications keep their own filename extensions. Darkbox does not require applications to share a data model.

## Why Darkbox exists

Darkbox was conceived by Vincenzo Petrucci as a common project-file format for software developed by [Illegal Studio](https://illegal.studio). It is a universal specification that other applications can also adopt.

A person's work should remain accessible beyond the lifetime of the software used to create it. Darkbox aims to make project files understandable and recoverable with documented, widely available tools, even when the original application is no longer available. Documentation travels with each file to help preserve the knowledge needed to interpret its contents.

Closed, undocumented formats can make people dependent on a particular application or vendor to access their own work, limiting their freedom to inspect, preserve, move and reuse what they have created. Darkbox is built on the principle that users' rights over their own creations should not depend on the continued existence of the software used to make them.

Preserving data also means preserving how to decode it. Every archive carries three levels of documentation: the Darkbox README for the container, the original SQLite file-format reference for the database's physical bytes, and the application profile for the meaning of its tables, records and resources. That knowledge travels with the project so it can remain useful beyond the software and websites that originally explained it.

## Documents

- [Specification](docs/specification.md)
- [Canonical Darkbox 1.0.0 README](archive/1.0.0/README.md), copied byte-for-byte to the archive root as `README.md`
- [Original SQLite file-format reference](archive/1.0.0/docs/sqlite/fileformat2.html), included with its [source and distribution notes](archive/1.0.0/docs/sqlite/SOURCE.md)
- [Manifest JSON Schema](schema/manifest.schema.json), using JSON Schema Draft 2020-12
- [Example manifests](examples/README.md) for two fictional application profiles
- [Application profile guidance](docs/profiles.md)

## Versioned archive documentation

The entire `archive/<darkbox.version>/` directory is the canonical documentation bundle for that version. Copy all its contents into the ZIP root, preserving every relative path and file's bytes. Do not add an enclosing `archive/` or version directory inside the ZIP. Then add the manifest, application profile documentation, databases and resources at their declared paths.

For version `1.0.0`, the [bundle](archive/1.0.0/) contains the canonical README and the captured SQLite documentation under `docs/sqlite/`, including its local presentation assets and upstream public-domain notice. Select the directory matching the declared version, rather than automatically using the newest bundle or fetching current SQLite pages while saving a project.

Published version directories are retained unchanged. Each release provides the matching specification and manifest schema together with its complete canonical bundle. Darkbox-authored text uses LF; `.gitattributes` protects both its line endings and the exact captured upstream bytes from checkout conversion.

## Minimal archive

```text
example.project
├── manifest.json
├── README.md
├── docs/
│   ├── profile.md
│   └── sqlite/           # complete canonical SQLite reference bundle
└── data/
    └── project.sqlite
```

Darkbox fixes its root metadata names and canonical bundle paths. Other database and folder paths are declared in the manifest. Required `application.profilePath` locates the included application data-format documentation; `docs/profile.md` is a recommended path. Attachments may remain database BLOBs or become separate files, as defined by a profile.

The specification version, application data-format version and optional creator-software version are independent. This version of the specification is identified by `darkbox.version = "1.0.0"`. Application profiles define their own data-format versions.

## License

The specification, schema, Darkbox-authored documentation, examples and Darkbox logo assets are licensed under the [MIT License](LICENSE). The original SQLite materials retain their upstream terms, recorded in the included [SQLite copyright notice](archive/1.0.0/docs/sqlite/copyright.html) and [source notes](archive/1.0.0/docs/sqlite/SOURCE.md). The license does not change ownership or licensing of project data packaged by applications. The canonical README includes the full MIT notice so it travels with distributed files. Permission to modify Darkbox materials does not alter conformance requirements, including the exact canonical bundle.
