#!/bin/sh
# Called after the corresponding image push. Metadata contains no private image address.
set +x
set -eu
umask 077
[ "$#" -eq 2 ] || exit 2
image=$1
prefix=$2
case "$prefix" in docker-linux|dockerhub-linux) ;; *) exit 2 ;; esac
arch=$(docker image inspect "$image" --format '{{.Architecture}}')
case "$arch" in amd64|arm64) ;; *) printf '%s\n' E_DOCKER_ARCH >&2; exit 2 ;; esac
[ "$(docker image inspect "$image" --format '{{.Os}}')" = linux ] || exit 2
version=$(sh ci/read-version.sh)
test -n "$version"
platform=$prefix-$arch
mkdir -p "release-out/$platform"
sh scripts/xil-version/prepare-release-json.sh --out "release-out/$platform/release.json" \
  --arch "$arch" --download-url "https://hub.docker.com/r/bgluminous/xilore-uptime/tags?name=$version"
RELEASE_PLATFORM_CODE=$platform sh scripts/version-publish/publish-version.sh validate \
  --backend github --input "release-out/$platform/release.json" --tag "$version"
