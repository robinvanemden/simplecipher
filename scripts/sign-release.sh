#!/bin/sh
# sign-release.sh — Sign release artifacts with a local key (outside CI).
#
# This adds a second layer of trust: CI produces Sigstore signatures
# (proving the artifact came from this repo's workflow), and the
# maintainer adds a detached signature (proving they reviewed it).
#
# Usage:
#   ./scripts/sign-release.sh v1.2.3
#
# Prerequisites:
#   - minisign (https://jedisct1.github.io/minisign/) or gpg
#   - The maintainer's signing key
#
# Outputs:
#   release/<artifact>.minisig  (minisign)
#   or release/<artifact>.asc   (gpg)

set -eu

TAG="${1:?Usage: $0 <tag>}"
DIR="release"

if [ ! -d "$DIR" ]; then
    echo "Downloading release artifacts for $TAG ..."
    mkdir -p "$DIR"
    gh release download "$TAG" --dir "$DIR"
fi

echo "Signing artifacts in $DIR/ ..."
for f in "$DIR"/simplecipher-linux-x86_64 \
         "$DIR"/simplecipher-linux-aarch64 \
         "$DIR"/simplecipher-win-x86_64.exe \
         "$DIR"/simplecipher-win-aarch64.exe \
         "$DIR"/simplecipher-minimal.apk \
         "$DIR"/simplecipher-full.apk \
         "$DIR"/SHA256SUMS.txt; do
    [ -f "$f" ] || continue
    if command -v minisign >/dev/null 2>&1; then
        minisign -Sm "$f"
        echo "  signed: ${f}.minisig"
    elif command -v gpg >/dev/null 2>&1; then
        gpg --detach-sign --armor "$f"
        echo "  signed: ${f}.asc"
    else
        echo "ERROR: neither minisign nor gpg found" >&2
        exit 1
    fi
done

echo ""
echo "Upload signatures to the release:"
echo "  gh release upload $TAG $DIR/*.minisig  (or *.asc)"
