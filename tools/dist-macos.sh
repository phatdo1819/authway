#!/bin/sh
# Builds the release for macOS: dist/<name>-<version>-macos.pkg, one package for Apple silicon and Intel with the
# app, its service, wireguard-go and the licenses. On a Mac with Xcode or its Command Line Tools, the Rust targets
# aarch64-apple-darwin and x86_64-apple-darwin, and tools/fetch-wireguard-go.sh run once before.
#   tools/dist-macos.sh
# Signed ad hoc, enough for a Mac that builds its own package. With certificates of Apple, for other Macs:
#   SIGN_APP="Developer ID Application: ..." SIGN_PKG="Developer ID Installer: ..." tools/dist-macos.sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
# the names of the app, as the program has them
product_value() {
    sed -n "s/^pub const $1: &str = \"\(.*\)\";/\1/p" "$root/src/product.rs"
}
PRODUCT=$(product_value PRODUCT)
BUNDLE_ID=$(product_value BUNDLE_ID)
EXECUTABLE=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
SUPPORT_DIR="/Library/Application Support/$PRODUCT"

wireguard="$root/wireguard/macos"
if [ ! -x "$wireguard/wireguard-go" ]; then
    echo "$wireguard/wireguard-go is missing: run tools/fetch-wireguard-go.sh" >&2
    exit 1
fi

# the oldest macOS of the package, for both
export MACOSX_DEPLOYMENT_TARGET=11.0
for target in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release --target "$target" --manifest-path "$root/Cargo.toml"
done

work="$root/target/pkg"
rm -rf "$work"
payload="$work/root"
app="$payload/Applications/$PRODUCT.app"
support="$payload$SUPPORT_DIR"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$support" "$payload/Library/LaunchDaemons" \
    "$payload/Library/LaunchAgents" "$work/scripts" "$work/resources" "$root/dist"

fill() {
    sed -e "s|@PRODUCT@|$PRODUCT|g" -e "s|@BUNDLE_ID@|$BUNDLE_ID|g" -e "s|@EXECUTABLE@|$EXECUTABLE|g" \
        -e "s|@VERSION@|$VERSION|g" -e "s|@SUPPORT_DIR@|$SUPPORT_DIR|g" -e "s|@COMPONENT@|#$BUNDLE_ID.pkg|g" \
        "$1" > "$2"
}

# the scripts, with the names of common.sh
sed -e "s|^PRODUCT=.*|PRODUCT=\"$PRODUCT\"|" -e "s|^BUNDLE_ID=.*|BUNDLE_ID=\"$BUNDLE_ID\"|" \
    -e "s|^EXECUTABLE=.*|EXECUTABLE=\"$EXECUTABLE\"|" "$root/installer/macos/common.sh" > "$work/common.sh"
script() {
    awk -v common="$work/common.sh" \
        '/^#@COMMON@$/ { while ((getline line < common) > 0) print line; next } { print }' "$1" > "$2"
    chmod 755 "$2"
}

# the app, for both processors
lipo -create -output "$app/Contents/MacOS/$EXECUTABLE" \
    "$root/target/aarch64-apple-darwin/release/$EXECUTABLE" "$root/target/x86_64-apple-darwin/release/$EXECUTABLE"
fill "$root/installer/macos/Info.plist" "$app/Contents/Info.plist"
cp "$root/LICENSE" "$app/Contents/Resources/LICENSE.txt"
iconset="$work/AppIcon.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$root/assets/app-macos.png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z "$double" "$double" "$root/assets/app-macos.png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"

# the service: its own copy, in a folder that only root can change, with wireguard-go and uninstall.sh
cp "$app/Contents/MacOS/$EXECUTABLE" "$support/$EXECUTABLE"
cp "$wireguard/wireguard-go" "$support/wireguard-go"
cp "$wireguard/wireguard-go-LICENSE.txt" "$support/wireguard-go-LICENSE.txt"
cp "$root/LICENSE" "$support/LICENSE.txt"
script "$root/installer/macos/uninstall.sh" "$support/uninstall.sh"
fill "$root/installer/macos/service.plist" "$payload/Library/LaunchDaemons/$BUNDLE_ID.service.plist"
fill "$root/installer/macos/agent.plist" "$payload/Library/LaunchAgents/$BUNDLE_ID.plist"
script "$root/installer/macos/preinstall" "$work/scripts/preinstall"
script "$root/installer/macos/postinstall" "$work/scripts/postinstall"

# the signatures: the programs first, then the app around them
if [ -n "${SIGN_APP:-}" ]; then
    set -- --force --timestamp --options runtime --sign "$SIGN_APP"
else
    set -- --force --sign -
fi
codesign "$@" --identifier "$BUNDLE_ID.wireguard-go" "$support/wireguard-go"
codesign "$@" --identifier "$BUNDLE_ID.service" "$support/$EXECUTABLE"
codesign "$@" --identifier "$BUNDLE_ID" "$app"
codesign --verify --strict "$app"

# the app goes to /Applications, even where another copy of it is
pkgbuild --analyze --root "$payload" "$work/components.plist"
index=0
while /usr/libexec/PlistBuddy -c "Print :$index" "$work/components.plist" >/dev/null 2>&1; do
    /usr/libexec/PlistBuddy -c "Set :$index:BundleIsRelocatable false" "$work/components.plist"
    index=$((index + 1))
done
pkgbuild --root "$payload" --component-plist "$work/components.plist" --identifier "$BUNDLE_ID" \
    --version "$VERSION" --install-location / --scripts "$work/scripts" "$work/$BUNDLE_ID.pkg"

fill "$root/installer/macos/Distribution.xml" "$work/Distribution.xml"
cp "$root/LICENSE" "$work/resources/LICENSE.txt"
package="$root/dist/$EXECUTABLE-$VERSION-macos.pkg"
if [ -n "${SIGN_PKG:-}" ]; then
    set -- --sign "$SIGN_PKG"
else
    set --
fi
productbuild --distribution "$work/Distribution.xml" --resources "$work/resources" --package-path "$work" \
    "$@" "$package"
echo "$package: $(du -k "$package" | cut -f 1) KB, SHA-256 $(shasum -a 256 "$package" | cut -d ' ' -f 1)"
