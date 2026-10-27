#!/bin/sh
# Removes the app from this Mac, with its VPNs and the data of every user:
#   sudo "/Library/Application Support/Authway/uninstall.sh"
# The settings of the administrator, /Library/Preferences/<bundle id>.plist or a profile, stay.

#@COMMON@
# run from the repository: the names next to it
if [ -z "${PRODUCT:-}" ]; then
    . "$(dirname "$0")/common.sh"
fi

if [ "$(id -u)" != 0 ]; then
    exec sudo /bin/sh "$0" "$@"
fi

echo "Removing $PRODUCT..."
quit_apps
for uid in $(dscl . -list /Users UniqueID | awk '$2 >= 500 { print $2 }'); do
    launchctl bootout "gui/$uid/$BUNDLE_ID" 2>/dev/null
done
stop_service

# The data of each user: the passwords in the keychain, the settings, the log. The keychain of a user who isn't
# logged in is locked: their saved passwords stay in it, under "$PRODUCT/http://...".
for user in $(dscl . -list /Users UniqueID | awk '$2 >= 500 { print $1 }'); do
    uid=$(id -u "$user" 2>/dev/null) || continue
    home=$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')
    [ -d "$home/Library/Application Support/$PRODUCT" ] || [ -d "$home/Library/Logs/$PRODUCT" ] || continue
    if [ -x "$EXE" ]; then
        if launchctl print "gui/$uid" >/dev/null 2>&1; then
            launchctl asuser "$uid" sudo -H -u "#$uid" "$EXE" --remove-user-data
        else
            sudo -H -u "#$uid" "$EXE" --remove-user-data
        fi
    fi
    rm -rf "$home/Library/Application Support/$PRODUCT" "$home/Library/Logs/$PRODUCT"
done

rm -rf "$APP" "$SUPPORT" "$LOGS" "$DAEMON_PLIST" "$AGENT_PLIST" "/var/run/$EXECUTABLE.sock"
pkgutil --forget "$BUNDLE_ID" >/dev/null 2>&1
echo "$PRODUCT is removed."
exit 0
