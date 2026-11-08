#!/bin/sh
# Install the ModSecurity Manager module into a local Webmin.
#
#   sudo ./install.sh
#
# Environment overrides:
#   WEBMIN_ROOT    Webmin program directory   (default /usr/share/webmin)
#   WEBMIN_CONFIG  Webmin config directory    (default /etc/webmin)
#   WEBMIN_USERS   Webmin users to grant the module to, space-separated
#                  (default "root"; set to "" to skip)
set -eu

MODULE="modsec-manager"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WEBMIN_ROOT="${WEBMIN_ROOT:-/usr/share/webmin}"
WEBMIN_CONFIG="${WEBMIN_CONFIG:-/etc/webmin}"
WEBMIN_USERS="${WEBMIN_USERS-root}"
SRC="$SCRIPT_DIR/$MODULE"
DEST="$WEBMIN_ROOT/$MODULE"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0"
  exit 1
fi
if [ ! -d "$WEBMIN_ROOT" ]; then
  echo "Webmin root not found at $WEBMIN_ROOT"
  echo "Set WEBMIN_ROOT=/path/to/webmin and run again."
  exit 1
fi
if [ ! -f "$SRC/module.info" ]; then
  echo "Module source not found at $SRC"
  exit 1
fi

# Program files
install -d -m 755 "$DEST"
cp -R "$SRC"/. "$DEST/"
find "$DEST" -name '.DS_Store' -delete
chown -R root:root "$DEST"
find "$DEST" -type d -exec chmod 755 {} \;
find "$DEST" -type f -exec chmod 644 {} \;
find "$DEST" -type f -name '*.cgi' -exec chmod 755 {} \;

if [ -d "$WEBMIN_CONFIG" ]; then
  # Webmin reads module settings from $WEBMIN_CONFIG/<module>/config, not from
  # the copy in the program directory. Keep any existing settings.
  install -d -m 700 "$WEBMIN_CONFIG/$MODULE"
  if [ ! -f "$WEBMIN_CONFIG/$MODULE/config" ]; then
    install -m 600 "$SRC/config" "$WEBMIN_CONFIG/$MODULE/config"
    echo "Created $WEBMIN_CONFIG/$MODULE/config"
  else
    # Add settings introduced by newer versions without touching existing ones.
    while IFS= read -r line; do
      key=${line%%=*}
      [ -n "$key" ] || continue
      if ! grep -q "^$key=" "$WEBMIN_CONFIG/$MODULE/config"; then
        echo "$line" >> "$WEBMIN_CONFIG/$MODULE/config"
        echo "Added new setting $key"
      fi
    done < "$SRC/config"
  fi

  # A module copied by hand is invisible until a Webmin user is granted it.
  ACL="$WEBMIN_CONFIG/webmin.acl"
  if [ -n "$WEBMIN_USERS" ] && [ -f "$ACL" ]; then
    for u in $WEBMIN_USERS; do
      if grep -q "^$u:" "$ACL"; then
        if ! grep -Eq "^$u:(.*[[:space:]])?$MODULE([[:space:]]|\$)" "$ACL"; then
          cp -p "$ACL" "$ACL.modsec-manager.bak"
          sed -i "s/^$u:.*/& $MODULE/" "$ACL"
          echo "Granted $MODULE to Webmin user $u"
        fi
      else
        echo "Webmin user $u not found in $ACL; grant the module in Webmin Users."
      fi
    done
  fi

  # Make Webmin rebuild its module list.
  rm -f "$WEBMIN_CONFIG/module.infos.cache"
fi

echo "Installed $MODULE into $DEST"
echo "Open Webmin > Servers > ModSecurity Manager (refresh modules or restart Webmin if it is not listed)."
