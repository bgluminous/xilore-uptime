#!/bin/sh
# GitLab after_script: retain release-out until artifacts have been uploaded.
# Only invoke in a disposable CI checkout. Never run against a developer checkout.
set -eu
[ "${GITLAB_CI:-}" = true ] || exit 0
[ -n "${CI_PROJECT_DIR:-}" ] && [ "$CI_PROJECT_DIR" != / ] || exit 2
cleanup_root=$(CDPATH= cd -P "$CI_PROJECT_DIR" && pwd) || exit 2
[ "$cleanup_root" != / ] && [ "$cleanup_root" = "$(pwd -P)" ] || exit 2
command -v rm >/dev/null 2>&1 || { printf '%s\n' E_DEPENDENCY_rm >&2; exit 2; }
for cleanup_entry in ./* ./.[!.]* ./..?*; do
    [ -e "$cleanup_entry" ] || [ -L "$cleanup_entry" ] || continue
    [ "$cleanup_entry" != ./release-out ] || continue
    rm -rf "$cleanup_entry"
done
