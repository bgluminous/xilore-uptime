#!/bin/sh
# Reuse the build job's metadata; never rebuild, recompute notes or enable overwrite.
set +x
set -eu
version=$(sh ci/read-version.sh)
test -n "$version"
[ "${CI_COMMIT_BRANCH:-}" = "release-$version" ] || exit 2
. ./scripts/xil-version/common.sh
xil_require awk
xil_temp
found=false
# Check every saved artifact before the first external write; retries keep its notes.
for platform in docker-linux-amd64 docker-linux-arm64 dockerhub-linux-amd64 dockerhub-linux-arm64; do
  input=release-out/$platform/release.json
  [ -f "$input" ] || continue
  found=true
  RELEASE_PLATFORM_CODE=$platform sh scripts/version-publish/publish-version.sh validate \
    --backend github --input "$input" --tag "$version"
  sh scripts/version-publish/json-tool.sh get "$input" changelog > "$xil_tmp/changelog"
  LC_ALL=C awk -f scripts/xil-version/check-changelog.awk "$xil_tmp/changelog"
done
[ "$found" = true ] || { printf '%s\n' E_RELEASE_INPUT_MISSING >&2; exit 2; }
for platform in docker-linux-amd64 docker-linux-arm64 dockerhub-linux-amd64 dockerhub-linux-arm64; do
  input=release-out/$platform/release.json
  [ -f "$input" ] || continue
  RELEASE_PLATFORM_CODE=$platform sh scripts/version-publish/publish-version.sh publish \
    --backend github --input "$input" --tag "$version"
done
