#!/bin/sh
# Build the Webmin module package (.wbm.gz) and a source tarball.
set -eu
cd "$(dirname -- "$0")"

MODULE="modsec-manager"
VERSION=$(sed -n 's/^version=//p' "$MODULE/module.info")

find "$MODULE" -name '.DS_Store' -delete
chmod 755 "$MODULE"/*.cgi
chmod 644 "$MODULE"/*.pl "$MODULE"/config "$MODULE"/config.info "$MODULE"/module.info "$MODULE"/defaultacl "$MODULE"/lang/*

# Files must be owned by root when Webmin unpacks the archive, and macOS tar
# must not add AppleDouble (._*) files or extended attribute headers.
if tar --version 2>/dev/null | grep -q bsdtar; then
  export COPYFILE_DISABLE=1
  OWNER="--uid 0 --gid 0 --uname root --gname root --no-mac-metadata --no-xattrs"
else
  OWNER="--owner=0 --group=0 --numeric-owner"
fi

# shellcheck disable=SC2086
tar $OWNER -czf "$MODULE.wbm.gz" "$MODULE"
# shellcheck disable=SC2086
tar $OWNER -czf "webmin-$MODULE-$VERSION.tar.gz" "$MODULE" README.md install.sh build.sh

echo "Built $MODULE.wbm.gz and webmin-$MODULE-$VERSION.tar.gz (version $VERSION)"
