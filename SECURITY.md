# Security policy

Darkbox reads untrusted files and ships cryptographic code, so reports about either are welcome.

## Supported versions

Security fixes are released for the latest published version of the `darkbox` crate and command-line tool. Published specification versions are immutable: a flaw in a specification text is corrected in a new specification version, and the reference implementation keeps reading every published version.

## Reporting a vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a suspected vulnerability.

Include what you can of the following:

- the affected version (`darkbox --version`) and platform;
- a minimal package or input that triggers the problem, or the steps to build one;
- what you observed and what you expected, for example a crash, a hang, a check that passes when it should fail, or bytes written outside the intended destination.

You will receive an acknowledgement, and a fix or an explanation follows as soon as the report is understood. Credit is given in the release notes unless you prefer otherwise.

## Scope

In scope:

- memory or resource exhaustion that escapes the configured `Limits`;
- a package that passes `verify` while violating a rule of its declared specification version;
- any write outside the requested destination, or modification of an input package;
- weaknesses in the protection extension (AES-256-GCM blocks, Ed25519 manifest signatures, the signed inventory) or in how the SDK handles keys;
- execution of SQL, commands or SQLite extensions supplied by a package.

Out of scope: packages that are merely invalid and are reported as invalid, application-profile semantics that no registered verifier implements, and the plaintext trusted-folder security mode of the sync extension, which is documented as providing no confidentiality against whoever can read the synchronized folder.

## Hardening in this repository

- `unsafe` code is forbidden in the crate.
- Dependencies are checked for advisories, license and source policy by `cargo deny` (`deny.toml`).
- Fuzz targets for the untrusted-input entry points live in `fuzz/`.
- The conformance corpus in `conformance/` pins the expected outcome of valid, invalid and unsupported packages.
