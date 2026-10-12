#!/usr/bin/env bash
# Sign the executable before packaging; notarize the final ZIP before publication.
set -euo pipefail

case "${1:-}" in
  sign)
    : "${APPLE_CERTIFICATE_P12:?Missing Apple certificate}"
    : "${APPLE_CERTIFICATE_PASSWORD:?Missing certificate password}"
    : "${APPLE_SIGNING_IDENTITY:?Missing signing identity}"
    : "${RUNNER_TEMP:?This script is intended for a GitHub macOS runner}"
    signing_dir=$(mktemp -d "$RUNNER_TEMP/darkbox-signing.XXXXXX")
    keychain="$signing_dir/signing.keychain-db"
    trap 'security delete-keychain "$keychain" >/dev/null 2>&1 || true; rm -rf "$signing_dir"' EXIT
    printf '%s' "$APPLE_CERTIFICATE_P12" | base64 --decode > "$signing_dir/certificate.p12"
    password=$(openssl rand -hex 32)
    security create-keychain -p "$password" "$keychain"
    security set-keychain-settings -lut 21600 "$keychain"
    security unlock-keychain -p "$password" "$keychain"
    security import "$signing_dir/certificate.p12" -k "$keychain" -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
    codesign --force --options runtime --sign "$APPLE_SIGNING_IDENTITY" --keychain "$keychain" --timestamp target/release/darkbox
    codesign --verify --strict --verbose=2 target/release/darkbox
    ;;
  submit)
    : "${APPLE_ID:?Missing Apple ID}"
    : "${APPLE_TEAM_ID:?Missing Apple team ID}"
    : "${APPLE_APP_PASSWORD:?Missing notarization password}"
    : "${RUNNER_TEMP:?This script is intended for a GitHub macOS runner}"
    submit_dir=$(mktemp -d "$RUNNER_TEMP/darkbox-notarization.XXXXXX")
    trap 'rm -rf "$submit_dir"' EXIT
    version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
    xcrun notarytool submit "dist/darkbox_${version}_darwin_arm64.zip" \
      --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" \
      --wait --timeout 30m --output-format json > "$submit_dir/result.json"
    python3 - "$submit_dir/result.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
if result.get('status') != 'Accepted':
    raise SystemExit('Notarization was not accepted: ' + str(result.get('status')))
print('Apple notarization accepted: ' + result['id'])
PY
    ;;
  *) printf 'Usage: %s sign|submit\n' "$0" >&2; exit 2 ;;
esac
