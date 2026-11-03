# The names and the steps that preinstall, postinstall and uninstall.sh share: tools/dist-macos.sh copies this
# file into each of them, with the names of src/product.rs.

PRODUCT="Authway"
BUNDLE_ID="io.authway.client"
EXECUTABLE="authway"

APP="/Applications/$PRODUCT.app"
EXE="$APP/Contents/MacOS/$EXECUTABLE"
SUPPORT="/Library/Application Support/$PRODUCT"
LOGS="/Library/Logs/$PRODUCT"
SERVICE="$BUNDLE_ID.service"
DAEMON_PLIST="/Library/LaunchDaemons/$SERVICE.plist"
AGENT_PLIST="/Library/LaunchAgents/$BUNDLE_ID.plist"

# the users whose app runs
app_users() {
    for pid in $(pgrep -f "^$EXE( |\$)"); do
        ps -o uid= -p "$pid"
    done | tr -d ' ' | sort -u
}

# Each app quits as when the user chooses Quit: it logs out of the login pages and turns its VPNs off. One that
# doesn't answer is stopped.
quit_apps() {
    for uid in $(app_users); do
        launchctl asuser "$uid" sudo -u "#$uid" /usr/bin/osascript \
            -e 'with timeout of 20 seconds' -e "tell application id \"$BUNDLE_ID\" to quit" -e 'end timeout' \
            >/dev/null 2>&1
    done
    waited=0
    while [ -n "$(app_users)" ] && [ "$waited" -lt 20 ]; do
        sleep 1
        waited=$((waited + 1))
    done
    pkill -f "^$EXE( |\$)" 2>/dev/null
    return 0
}

# the service turns its tunnels off and puts the DNS servers back as it stops
stop_service() {
    launchctl bootout "system/$SERVICE" 2>/dev/null
    return 0
}

# The launchd jobs of the app under another identifier, from an earlier version: found by the program they start,
# stopped and removed, so one service only owns the socket. Then the receipts of those packages.
remove_other_jobs() {
    for plist in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist; do
        [ -f "$plist" ] || continue
        case "$plist" in
            "$DAEMON_PLIST" | "$AGENT_PLIST") continue ;;
        esac
        grep -q -F -e "<string>$SUPPORT/$EXECUTABLE</string>" -e "<string>$EXE</string>" "$plist" || continue
        label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null) || continue
        case "$plist" in
            /Library/LaunchDaemons/*)
                launchctl bootout "system/$label" 2>/dev/null
                ;;
            *)
                for uid in $(dscl . -list /Users UniqueID | awk '$2 >= 500 { print $2 }'); do
                    launchctl bootout "gui/$uid/$label" 2>/dev/null
                done
                ;;
        esac
        rm -f "$plist"
    done
    for id in $(pkgutil --file-info "$APP" 2>/dev/null | awk '/^pkgid: / { print $2 }'); do
        [ "$id" = "$BUNDLE_ID" ] || pkgutil --forget "$id" >/dev/null 2>&1
    done
    return 0
}
