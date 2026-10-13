#!/bin/sh
# Project hooks are trusted code. Metadata is always data, never sourced/eval'ed.
set +x
set -eu
set -f
umask 077
fail() { printf '%s\n' "$1" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || fail "E_DEPENDENCY_$1"; }
for tool in sh dirname awk; do need "$tool"; done
dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
phase=${1:-}; backend=${RELEASE_BACKEND:-}
case "$phase" in prepare|upload|publish) ;; *) fail E_CI_PHASE ;; esac
case "$backend" in xil|github) ;; *) fail E_CI_BACKEND ;; esac
[ -n "${RELEASE_PROJECT_CODE:-}" ] && [ "$RELEASE_PROJECT_CODE" != CHANGE_ME ] || fail E_PROJECT_CONFIGURATION_REQUIRED
platform=${RELEASE_PLATFORM_CODE:-}
case "$platform" in ''|.|..|*[!A-Za-z0-9._-]*) fail E_PLATFORM ;; esac
work=release-out/$platform
asset_name=${RELEASE_ASSET_FILE:-app.tar.gz}
case "$asset_name" in ''|.*|*.|*[!A-Za-z0-9._-]*) fail E_ASSET_NAME ;; esac
asset=$work/$asset_name
mode=${RELEASE_ASSET_MODE:-upload}
case "$mode" in upload|existing) ;; *) fail E_ASSET_MODE ;; esac
if [ "$backend" = xil ] && [ "$mode" != upload ]; then fail E_XIL_UPLOAD_HOOK_REQUIRED; fi
version_hook=${RELEASE_VERSION_HOOK:-ci/read-version.sh}
[ -r "$version_hook" ] || fail E_VERSION_HOOK_REQUIRED
raw_version=$(sh "$version_hook") || fail E_VERSION_HOOK
version=$(sh "$dir/json-tool.sh" version "$raw_version") || fail E_VERSION
branch=${CI_COMMIT_BRANCH:-}
if [ "${GITHUB_ACTIONS:-false}" = true ]; then
    [ "${GITHUB_REF_TYPE:-}" = branch ] || fail E_RELEASE_BRANCH
    branch=${GITHUB_REF_NAME:-}
fi
branch_version=$(sh "$dir/json-tool.sh" ref "$branch") || fail E_RELEASE_BRANCH
[ "$version" = "$branch_version" ] || fail E_BRANCH_VERSION_MISMATCH
if [ "$phase" = prepare ]; then
    need mkdir
    mkdir -p "$work"
    sh "$dir/json-tool.sh" make "$version" > "$work/release.json"
    sh "$dir/publish-version.sh" validate --backend "$backend" --input "$work/release.json" --tag "$version"
    if [ "$mode" = upload ]; then
        build_hook=${RELEASE_BUILD_HOOK:-ci/build-release.sh}
        [ -r "$build_hook" ] || fail E_BUILD_HOOK_REQUIRED
        sh "$build_hook" "$platform" "$asset" || fail E_BUILD_HOOK
        [ -s "$asset" ] || fail E_BUILD_ARTIFACT_REQUIRED
    fi
    exit 0
fi
[ -r "$work/release.json" ] || fail E_RELEASE_ARTIFACT_REQUIRED
prepared_version=$(sh "$dir/json-tool.sh" get "$work/release.json" version) || fail E_RELEASE_ARTIFACT
[ "$prepared_version" = "$version" ] || fail E_ARTIFACT_VERSION_MISMATCH
if [ "$phase" = upload ]; then
    need cat
    [ "$backend" = xil ] || fail E_UPLOAD_PHASE_BACKEND
    upload_hook=${RELEASE_UPLOAD_HOOK:-ci/upload-release.sh}
    [ -r "$upload_hook" ] && [ -s "$asset" ] || fail E_UPLOAD_HOOK_REQUIRED
    sh "$upload_hook" "$asset" "$work/download-url.txt" || fail E_UPLOAD_HOOK
    [ -s "$work/download-url.txt" ] || fail E_DOWNLOAD_URL_REQUIRED
    download_url=$(cat "$work/download-url.txt")
    VP_OP=url VP_FILE=$work/release.json VP_VALUE=$download_url LC_ALL=C \
        awk -f "$dir/json.awk" -f "$dir/release.awk" > "$work/ready.json"
    sh "$dir/publish-version.sh" validate --backend xil --input "$work/ready.json" --tag "$version"
    exit 0
fi
if [ "$backend" = xil ]; then
    [ -r "$work/ready.json" ] || fail E_UPLOAD_RESULT_REQUIRED
    exec sh "$dir/publish-version.sh" publish --backend xil --input "$work/ready.json" --tag "$version"
fi
set -- sh "$dir/publish-version.sh" publish --backend github --input "$work/release.json" --tag "$version"
if [ "$mode" = upload ]; then set -- "$@" --asset "$asset"; fi
exec "$@"
