#!/bin/sh
# Reuse the build job's metadata; never rebuild, recompute notes or enable overwrite.
set +x
set -eu
version=$(sh ci/read-version.sh)
test -n "$version"
[ "${CI_COMMIT_BRANCH:-}" = "release-$version" ] || exit 2
found=false
for platform in docker-linux-amd64 docker-linux-arm64 dockerhub-linux-amd64 dockerhub-linux-arm64; do
  input=release-out/$platform/release.json
  [ -f "$input" ] || continue
  found=true
  RELEASE_PLATFORM_CODE=$platform sh scripts/version-publish/publish-version.sh publish \
    --backend github --input "$input" --tag "$version"
done
[ "$found" = true ] || { printf '%s\n' E_RELEASE_INPUT_MISSING >&2; exit 2; }
