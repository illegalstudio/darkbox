# Darkbox conformance corpus

This directory holds test packages for implementers of the Darkbox specification. It is independent of any programming language: each case is a file plus its expected outcome. An implementation that claims to verify a common version should agree with every case for that version.

## Layout

```text
conformance/
└── 1.6.0/
    ├── cases.json
    ├── valid-minimal.zip
    ├── invalid-modified-readme.zip
    └── ...
```

There is one directory per common specification version. `cases.json` has this shape:

```json
{
  "darkbox": "1.6.0",
  "outcomes": { "valid": "...", "invalid": "...", "unsupported": "..." },
  "cases": [
    {
      "id": "invalid-modified-readme",
      "file": "invalid-modified-readme.zip",
      "expected": "invalid",
      "section": "5",
      "description": "The canonical README.md has one appended line.",
      "referenceDiagnostic": "bundle.file",
      "sha256": "..."
    }
  ]
}
```

| Member | Meaning |
| --- | --- |
| `id` | Stable case identifier. |
| `file` | The package, relative to the version directory. |
| `expected` | The required outcome: `valid`, `invalid` or `unsupported`. |
| `section` | The section of that version's specification the case exercises. |
| `description` | What the package contains or what was changed. |
| `referenceDiagnostic` | The diagnostic code reported by the Rust reference implementation, or `null` for a valid package. Informative: other implementations need not use the same codes. |
| `sha256` | Lowercase SHA-256 of the file, to detect a damaged copy of the corpus. |

## Outcomes

- `valid`: every common machine-checkable rule passes. Application-profile semantics are outside the corpus: all cases use a fictional profile that no verifier implements.
- `invalid`: a rule of the declared common version is violated, or data is damaged.
- `unsupported`: the package needs a common version or an extension the reader does not implement. A reader must keep this distinct from corruption (section 8 of the specification).

A resource-limit failure is a fourth outcome that depends on reader policy, so the corpus has no case for it. No case needs limits above a few megabytes.

## Using the corpus

Verify each `file` offline with default settings, without signer keys, decryption keys or application profiles, and compare the result with `expected`. A reader must never modify a case file.

The cases assume a reader that implements common version 1.6.0, protection extension 1.0.0 and sync extension 1.1.0, and no other extension. `unsupported-official-extension-version` uses a deliberately nonexistent official extension, and `unsupported-common-version` a nonexistent common version.

## Scope

Every case of this first corpus is a ZIP package. Directory packages, delta transfers, protected packages and sync checkpoints are not covered here: protection and sync ship their own interoperable vectors in their extension bundles, and an empty declared folder cannot be stored in a Git checkout as a plain directory.

## Maintenance

The archives are committed test vectors. The Rust test `tests/conformance.rs` checks the reference implementation against them on every run. They are rebuilt only when cases are added or changed:

```sh
cargo test --test conformance -- --ignored regenerate_corpus
```

Regeneration is not byte-reproducible across SQLite or compression library versions, so it rewrites every archive and digest. Review the resulting diff of `cases.json` before committing it.
