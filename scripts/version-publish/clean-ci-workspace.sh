#!/bin/sh
# GitLab after_script: retain release-out until artifacts have been uploaded.
# Only invoke in a disposable CI checkout. Never run against a developer checkout.
set -eu
[ "${GITLAB_CI:-}" = true ] || exit 0
[ -n "${CI_PROJECT_DIR:-}" ] && [ "$CI_PROJECT_DIR" != / ] || exit 2
case "$CI_PROJECT_DIR" in
    /*) cleanup_path=$CI_PROJECT_DIR ;;
    *)
        # SSH executors resolve relative checkout paths from the login user's home.
        case "${HOME:-}" in /*) ;; *) exit 2 ;; esac
        cleanup_path=$HOME/$CI_PROJECT_DIR
        ;;
esac
cleanup_root=$(CDPATH= cd -P "$cleanup_path" && pwd -P) || exit 2
[ "$cleanup_root" != / ] && [ "$cleanup_root" = "$(pwd -P)" ] || exit 2
script_root=$(CDPATH= cd -P "$(dirname "$0")/../.." && pwd -P) || exit 2
[ "$cleanup_root" = "$script_root" ] || exit 2
command -v rm >/dev/null 2>&1 || { printf '%s\n' E_DEPENDENCY_rm >&2; exit 2; }
for cleanup_entry in ./* ./.[!.]* ./..?*; do
    [ -e "$cleanup_entry" ] || [ -L "$cleanup_entry" ] || continue
    [ "$cleanup_entry" != ./release-out ] || continue
    rm -rf "$cleanup_entry"
done
