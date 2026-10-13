#!/usr/bin/env bash
# Sync origin/master to github/master and sync origin/release-<version> & github/release-<version>
# Usage: ./scripts/sync-release.sh <version>
# Example: ./scripts/sync-release.sh 1.0.2

set -e

VERSION="$1"
if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 1.0.2"
  exit 1
fi

RELEASE_BRANCH="release-${VERSION}"

echo "[SYNC] >>> Sync start. Version: ${VERSION}, release branch: ${RELEASE_BRANCH}"
echo ""

# Ensure we are at repo root
cd "$(dirname "$0")/.."

# Check remotes
if ! git remote get-url origin &>/dev/null; then
  echo "[ERROR] remote 'origin' not found."
  exit 1
fi
if ! git remote get-url github &>/dev/null; then
  echo "[ERROR] remote 'github' not found."
  echo "Hint: git remote add github <github-repo-url>"
  exit 1
fi

# Fetch latest origin/master
echo "[SYNC] >>> Fetch origin/master ..."
git fetch origin master

# Before creating release branch, ensure no same-name branch exists on remotes
echo "[SYNC] >>> Check if branch ${RELEASE_BRANCH} already exists on remotes ..."
if git ls-remote --heads origin "${RELEASE_BRANCH}" | grep -q .; then
  echo "[ERROR] origin already has branch ${RELEASE_BRANCH}. abort."
  exit 1
fi
if git ls-remote --heads github "${RELEASE_BRANCH}" | grep -q .; then
  echo "[ERROR] github already has branch ${RELEASE_BRANCH}. abort."
  exit 1
fi

# 1. Push origin/master -> github/master
echo "[SYNC] >>> Push origin/master -> github/master"
git push github origin/master:refs/heads/master

# 2. Create release-<version> on origin (based on origin/master)
echo "[SYNC] >>> Create branch ${RELEASE_BRANCH} on origin ..."
git push origin origin/master:refs/heads/"${RELEASE_BRANCH}"

# 3. Push origin/master -> github/release-<version>
echo "[SYNC] >>> Push origin/master -> github/${RELEASE_BRANCH}"
git push github origin/master:refs/heads/"${RELEASE_BRANCH}"

echo ""
echo "[SYNC] >>> Sync done: github/master and github/${RELEASE_BRANCH} are now same as origin/master."
