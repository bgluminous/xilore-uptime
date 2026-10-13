#!/bin/sh
set -eu
exec sh scripts/version-publish/json-tool.sh get package.json version
