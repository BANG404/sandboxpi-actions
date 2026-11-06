#!/usr/bin/env bash
set -euo pipefail

version=0.76.1
archive="trivy_${version}_Linux-64bit.tar.gz"
directory=$(mktemp -d)
trap 'rm -rf "$directory"' EXIT
cd "$directory"
base="https://github.com/aquasecurity/trivy/releases/download/v${version}"
curl --fail --silent --show-error --location --retry 3 --max-time 180 -O "$base/$archive"
curl --fail --silent --show-error --location --retry 3 --max-time 180 -O "$base/trivy_${version}_checksums.txt"
awk -v archive="$archive" '$2 == archive { print }' "trivy_${version}_checksums.txt" > selected.sha256
test "$(wc -l < selected.sha256)" -eq 1
sha256sum --check selected.sha256
tar -xzf "$archive" trivy
install -D -m 755 trivy "$RUNNER_TEMP/trivy-bin/trivy"
