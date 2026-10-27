# The names and the steps that preinstall, postinstall and uninstall.sh share: tools/dist-macos.sh copies this
# file into each of them, with the names of src/product.rs.

PRODUCT="Authway"
BUNDLE_ID="io.github.phatdo1819.authway"
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
