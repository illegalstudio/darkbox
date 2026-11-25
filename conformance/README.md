# Darkbox conformance corpus

This directory holds test packages for implementers of the Darkbox specification. It is independent of any programming language: each case is a file, the inputs a verifier needs for it, and its expected outcome. An implementation that claims to verify a common version should agree with every case for that version.

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
| `file` | The package or delta, relative to the version directory. Several cases can describe the same bytes under different inputs; each still has its own file. |
| `inputs` | Optional. What the verifier is given besides the file; see below. Absent when the case needs nothing. |
| `expected` | The required outcome: `valid`, `invalid` or `unsupported`. |
| `section` | The section of that version's specification the case exercises. |
| `description` | What the package contains or what was changed. |
| `referenceDiagnostic` | The diagnostic code reported by the Rust reference implementation, or `null` for a valid case. Informative: other implementations need not use the same codes. |
| `sha256` | Lowercase SHA-256 of the file, to detect a damaged copy of the corpus. |

## Inputs

A case without `inputs` is verified with nothing but the file. The members of `inputs` are all optional:

| Member | Meaning |
| --- | --- |
| `trustedSigners` | Object mapping signer identifiers to Ed25519 public keys, each as 64 lowercase hexadecimal digits. These are the only signers the verifier trusts for the case. |
| `decryptionKeys` | Object mapping key identifiers to AES-256 keys, each as 64 lowercase hexadecimal digits. |
| `base` | The file, relative to the version directory, of the complete base edition. When present, `file` is a delta transfer: verify that it applies to exactly this base and reconstructs a conforming target. |

The two key objects have the format of the key files accepted by the `darkbox` command-line tool. All keys in the corpus are fixed public test values and protect nothing.

## Outcomes

- `valid`: every common machine-checkable rule passes, together with the rules of the declared official extensions that the given inputs allow to check. Application-profile semantics are outside the corpus: all cases use a fictional profile that no verifier implements.
- `invalid`: a rule of the declared common version is violated, or data is damaged.
- `unsupported`: the package needs a common version or an extension the reader does not implement, or a protected package names a signer for which the case supplies no trusted key. A reader must keep this distinct from corruption (section 8 of the specification).

A resource-limit failure is a fourth outcome that depends on reader policy, so the corpus has no case for it. No case needs limits above a few megabytes.

## Using the corpus

Verify each `file` offline with default settings and without application profiles, giving the verifier exactly the signer keys, decryption keys and base edition listed in `inputs` and nothing else, then compare the result with `expected`. A reader must never modify a case file.

The cases assume a reader that implements common version 1.6.0, protection extension 1.0.0 and sync extension 1.1.0, and no other extension. `unsupported-official-extension-version` uses a deliberately nonexistent official extension, and `unsupported-common-version` a nonexistent common version.

## Scope

The corpus covers ZIP packages, packages protected with the official protection extension, and delta transfers. The protection cases exercise package-level rules (signature, signed inventory, binding of a block to its location); the block format itself has interoperable vectors in the protection extension bundle.

Directory packages and sync checkpoints are not covered. An empty declared folder cannot be stored in a Git checkout as a plain directory, and the live-directory rules add outcomes that depend on locks held at verification time. Sync ships its own interoperable vectors in its extension bundle.

## Maintenance

The archives are committed test vectors. The Rust test `tests/conformance.rs` checks the reference implementation against them on every run. After adding or changing a case, update the corpus with:

```sh
cargo test --test conformance -- --ignored regenerate_corpus
```

The command keeps the bytes of every archive that already exists, writes the archives that are missing, removes those whose case is gone, and rewrites `cases.json`. To rebuild a case, delete its archive first. A delta is bound to the exact bytes of its base edition, so rebuild `valid-package-identity.zip` and the delta cases together. Building an archive is not byte-reproducible across SQLite or compression library versions, which is why existing archives are never rewritten implicitly. Review the resulting diff of `cases.json` before committing it.
