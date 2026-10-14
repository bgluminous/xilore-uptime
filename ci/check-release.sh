#!/bin/sh
# Project release gate: validate settings and the reviewed changelog before building.
set +x
set -eu
[ "$#" -eq 2 ] && [ "$1" = --branch ] || { printf '%s\n' 'Usage: check-release.sh --branch release-X.Y.Z' >&2; exit 2; }
root=$(CDPATH= cd -P "$(dirname "$0")/.." && pwd)
CDPATH= cd -P "$root"
sh scripts/version-publish/check-version.sh --branch "$2"
. ./scripts/xil-version/common.sh
xil_temp
sh scripts/xil-version/prepare-release-json.sh --out "$xil_tmp/release.json" > /dev/null
printf '%s\n' 'validated release changelog'
