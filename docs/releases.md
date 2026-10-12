# Building and publishing releases

Software tags use `vMAJOR.MINOR.PATCH` and match the Rust package version in both `Cargo.toml` and `Cargo.lock`. Specification versions are registered separately in `versions.json`. A software patch can fix the validator without changing any specification or canonical document. Publishing a new specification requires its own completed versioned references, rules and tests.

## Prepare a release

Commit the intended changes first. From a clean `main` checkout with Python 3.11 or later, Make, Rust 1.88 or later, a C compiler and authenticated Git access to `origin`:

```sh
make release
```

The command fetches `origin/main` and tags, checks that the local branch contains the remote branch, and proposes the current Cargo version when it is newer than existing release tags. Otherwise it proposes the next patch version. For the first release it proposes `1.0.0`. Stable versions only are supported.

Select the software version and which unpublished specification versions to publish. The first release defaults to the prepared specification versions because a public binary must support at least one published specification. Later software releases default to publishing no new specification. An explicit specification selection sets `released: true` without rewriting its canonical files. Those references become immutable when the release is published.

The command updates only `Cargo.toml`, the Darkbox entry in `Cargo.lock`, and `versions.json`, then runs `make check` and the published-reference guard. Review its diff summary and confirm the final commit, tag and push. It commits changed preparation files, creates an annotated tag, and pushes the branch and tag together with `git push --atomic`. Cancelling or failing checks restores the preparation files. A failed push retains the local release commit and tag and prints the retry command.

Preview the proposed release without changing files, Git refs or the remote:

```sh
make release ARGS="--dry-run"
```

An explicit version or specification selection still requires the final interactive confirmation:

```sh
make release ARGS="--version 1.0.0 --publish-spec 1.0.0"
```

The command does not bypass branch protections. If `main` requires a pull request, prepare and review the release metadata through that process, then create an annotated matching tag on the merged commit and push that tag. Tagged CI requires the release commit to belong to `origin/main`.

## GitHub Actions

`ci.yml` calls the reusable `build.yml` workflow for branch pushes, pull requests and manual runs. It runs canonical catalog checks, Python release tests, Rust formatting, clippy and tests on each native platform, then builds and packages the executable. A separate Linux x86-64 job compiles the crate's binary and test targets with Rust 1.88 to check the declared minimum Rust version.

| Runner | Rust target | Package |
| --- | --- | --- |
| `ubuntu-22.04` | `x86_64-unknown-linux-gnu` | `darkbox_<version>_linux_amd64.tar.gz` |
| `ubuntu-22.04-arm` | `aarch64-unknown-linux-gnu` | `darkbox_<version>_linux_arm64.tar.gz` |
| `macos-15` | `aarch64-apple-darwin` | `darkbox_<version>_darwin_arm64.zip` |

Linux builds use Ubuntu 22.04 to keep the glibc baseline at 2.35. macOS builds set `MACOSX_DEPLOYMENT_TARGET=11.0`. Every package includes the binary, CLI documentation, MIT notice, locked dependency inventory, dependency licenses, Rust standard-library notices and the SQLite public-domain notice. The binary embeds all registered specification references and requires no network access at runtime.

`release.yml` runs on version-tag pushes or a manual dispatch naming an existing tag. Its preparation job checks the tag syntax, annotation, exact commit, Cargo versions, published-specification support, immutable earlier references and required credentials. All builds use the resolved commit. The shared build workflow signs the macOS executable with hardened runtime before packaging and requires Apple's notarization result to be `Accepted` for the final ZIP.

`pacman-build.yml` packages the checked Linux executables with `makepkg`, running as a non-root builder in Arch containers on native x86-64 and ARM64 runners. It generates a recipe from `packaging/arch/PKGBUILD.in` with the exact software version and upstream SHA-256, then uses a local checked archive cache because the release is not public yet. Packaging preserves executable bytes and all notices, declares glibc and gcc-libs dependencies, and disables stripping and debug-package splitting. The ARM job uses the same community `menci/archlinuxarm:base-devel` image as the Illegal Studio pacman repository's reusable build workflow.

Native packages are named `darkbox-<version>-1-x86_64.pkg.tar.zst` and `darkbox-<version>-1-aarch64.pkg.tar.zst`. `pkgrel=1` is the Arch packaging revision, separate from the software and specification versions. Package validation checks `.PKGINFO`, architecture, installed paths, notice inventory, executable permissions and exact upstream executable/documentation bytes. Ordinary CI also builds both Arch packages; no external repository is notified for development builds.

Publication waits for all platform checks, the minimum-Rust job and both Arch package jobs. It verifies the package set, executable architecture, executable permissions, documentation and SHA-256 files, then creates a private draft release. Only after all twelve assets are uploaded and checked does it publish the release: five packages, five individual `.sha256` files, one checksum list for the three portable archives and one for the two Arch packages. Published releases are never overwritten by the workflow. The source archives contain the versioned specification, schemas and canonical bundles.

After publication, `pacman.yml` sends `repository_dispatch` with event type `publish` and source `illegalstudio/darkbox` to `illegalstudio/pacman`. Its existing sync workflow registers the project, downloads the packages, updates each architecture's database and deploys GitHub Pages. This notification is explicitly called by the release workflow because publishing with `GITHUB_TOKEN` does not automatically trigger another release-event workflow, as described in [GitHub's workflow-triggering rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow). Homebrew and pacman notification run independently after the same complete GitHub release.

## Credentials and repository settings

Allow GitHub Actions in this repository. The release publishing job requests `contents: write`; other jobs use read-only repository tokens. Organization-level secrets must explicitly be accessible to this repository.

Use the same Apple signing and notarization secrets as the other Illegal Studio release workflows:

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE_P12` | Base64-encoded Developer ID Application certificate with private key |
| `APPLE_CERTIFICATE_PASSWORD` | Password for that certificate |
| `APPLE_SIGNING_IDENTITY` | Developer ID Application signing identity |
| `APPLE_ID` | Apple account used for notarization |
| `APPLE_TEAM_ID` | Apple developer team identifier |
| `APPLE_APP_PASSWORD` | App-specific password for notarization |

Signing imports the PKCS#12 certificate and private key into a temporary keychain, grants signing access and adds it to the user search list, following [GitHub's certificate installation workflow](https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications). Before signing, it checks that `APPLE_SIGNING_IDENTITY` matches exactly one valid imported Developer ID Application identity, then signs using that certificate's SHA-1 fingerprint. The secret accepts a certificate name or fingerprint. Failure messages identify the stage without printing credentials. Cleanup restores the original search list and removes the keychain and temporary files on success or failure.

The binary is a standalone command-line executable; its notarization ZIP is the distribution submitted to Apple. This pipeline does not staple a ticket to the ZIP. Apple records the accepted notarization separately, as described in its [notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

For Homebrew, provide `ILLEGAL_BOT_APP_ID` and `ILLEGAL_BOT_PRIVATE_KEY`. Install that GitHub App on `illegalstudio/homebrew-tap` with Contents read/write permission. The workflow creates a token scoped to that repository and writes `Formula/darkbox.rb` as `illegal-studio[bot]`. It uses the exact final GitHub package digests and installs both the executable and its notices. macOS Intel is intentionally unsupported.

GitHub's repository token cannot write to the separate tap. Keep the App credentials available to Darkbox even if the same App is already used by other projects. Consider enabling GitHub immutable releases and protecting published version tags; the local scripts do not change repository settings.

For pacman synchronization, use the same `ILLEGAL_BOT_APP_ID` and `ILLEGAL_BOT_PRIVATE_KEY` credentials. The GitHub App must also have access to `illegalstudio/pacman` with Contents read/write permission. The notification workflow creates a separate temporary installation token scoped to `pacman` and sends the synchronization event. No additional personal access token or dispatch-token secret is required. Release preparation checks the shared App credentials along with the Apple credentials. Packages are added through the repository's existing sync workflow under its unsigned policy.

## Retry a failed workflow

If validation, build, signing or notarization fails, nothing is published. Fix credentials or the environment and rerun the failed job or manually dispatch `Release` for the same tag. A partial upload leaves a draft; rerunning can replace its assets only when the draft still matches the checked commit. Review any reported conflicting draft rather than deleting or replacing a public release.

If Homebrew publication fails after the GitHub release is public, dispatch `Publish Homebrew formula` with that tag. It downloads and verifies the latest public release, regenerates the formula and commits only a changed formula. This recovery does not rebuild or modify released assets. Older releases cannot replace the latest tap formula. Concurrent tap changes cause a normal Git push failure; rerun to start from the new tap HEAD.

If the pacman notification fails, dispatch `Notify Illegal Studio pacman` with the latest published tag. It checks that both native packages exist and retries only synchronization. If notification succeeds but the external sync/deployment fails, rerun the sync workflow in `illegalstudio/pacman` for `illegalstudio/darkbox`. Darkbox's workflow confirms the dispatch was accepted; it does not wait for the external Pages deployment. The pacman repository also has a nightly catch-up for sources already registered by a successful sync.
