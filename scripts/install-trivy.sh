#!/bin/sh
# Install Trivy WITHOUT a GitHub Action: fixed version, checked against a fixed SHA-256 checksum.
# (trivy-action and setup-trivy were compromised in March 2026, CVE-2026-33634; Trivy 0.69.4 was a malicious release.)
# A new version is only taken over deliberately: version and checksum from the official checksums file of the
# release (trivy_<version>_checksums.txt), both entered here.
set -eu
TRIVY_VERSION="0.74.0"
TRIVY_SHA256="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"  # trivy_0.74.0_Linux-64bit.tar.gz

dest="${1:-${RUNNER_TEMP:-/tmp}/trivy-bin}"
archive="$(mktemp)"
url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
curl -fsSL --retry 3 --proto '=https' -o "$archive" "$url"
actual="$(sha256sum "$archive" | cut -d' ' -f1)"
# In addition: the pinned checksum must be the one in the official checksums file of the release
sums="$(curl -fsSL --retry 3 --proto '=https' "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt")"
official="$(printf '%s\n' "$sums" | awk -v f="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" '$2 == f {print $1}')"
if [ "$official" != "$TRIVY_SHA256" ]; then
    msg="Trivy ${TRIVY_VERSION}: pinned checksum differs from the official checksums file (${official:-missing}) - not used"
    echo "::error title=Trivy download::${msg}"
    echo "$msg" >&2
    exit 1
fi
if [ "$actual" != "$TRIVY_SHA256" ]; then
    msg="Trivy ${TRIVY_VERSION}: checksum does not match (expected ${TRIVY_SHA256}, got ${actual}) - not used"
    echo "::error title=Trivy download::${msg}"
    echo "$msg" >&2
    exit 1
fi
mkdir -p "$dest"
tar -xzf "$archive" -C "$dest" trivy
rm -f "$archive"
"$dest/trivy" --version
[ -z "${GITHUB_PATH:-}" ] || echo "$dest" >> "$GITHUB_PATH"
