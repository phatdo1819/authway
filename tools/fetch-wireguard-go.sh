#!/bin/sh
# Builds wireguard-go, the WireGuard of WireGuard LLC in user space, for dist-macos.sh: from its source release,
# which must have the expected SHA-256, for Apple silicon and Intel, in one universal binary in
# wireguard/macos/wireguard-go. Built as it is, never changed. Needs Go 1.23.1 or later, on a Mac.
#   tools/fetch-wireguard-go.sh [version sha256]
set -eu

VERSION="${1:-0.0.20250522}"
SHA256="${2:-c7eeffb13e5eb43b93e54a21d78dd71414771af9e07112da5275690493695c9c}"

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

command -v go >/dev/null || { echo "Go is missing: brew install go, or https://go.dev/dl/" >&2; exit 1; }
archive="$work/wireguard-go.tar.xz"
curl -fsSL -o "$archive" "https://git.zx2c4.com/wireguard-go/snapshot/wireguard-go-$VERSION.tar.xz"
hash=$(shasum -a 256 "$archive" | cut -d ' ' -f 1)
if [ "$hash" != "$SHA256" ]; then
    echo "wireguard-go-$VERSION.tar.xz has the SHA-256 $hash instead of $SHA256" >&2
    exit 1
fi
tar -xJf "$archive" -C "$work"
source="$work/wireguard-go-$VERSION"

for arch in arm64 amd64; do
    # as its Makefile builds it
    (cd "$source" && CGO_ENABLED=0 GOOS=darwin GOARCH=$arch GOFLAGS=-buildvcs=false \
        go build -trimpath -ldflags="-s -w" -o "$work/wireguard-go-$arch")
done
mkdir -p "$root/wireguard/macos"
lipo -create -output "$root/wireguard/macos/wireguard-go" "$work/wireguard-go-arm64" "$work/wireguard-go-amd64"
# its license goes with it
cp "$source/LICENSE" "$root/wireguard/macos/wireguard-go-LICENSE.txt"
lipo -info "$root/wireguard/macos/wireguard-go"
