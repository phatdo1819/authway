#!/bin/sh
# Builds the release for Linux: dist/<name>_<version>_<arch>.deb for Debian and Ubuntu, and
# dist/<name>-<version>-1.<arch>.rpm for RHEL, its rebuilds and Fedora, with the app, its service, the icons and the
# rules of polkit. Run it as a normal user, on Debian, Ubuntu, RHEL or Fedora:
#   tools/dist-linux.sh                                       for the processor of this computer
#   TARGET=aarch64-unknown-linux-gnu tools/dist-linux.sh      for ARM64, from x86_64 on Debian or Ubuntu
# It installs what the build needs and is missing, with sudo: a C compiler for the linker, dpkg-deb, rpmbuild, the
# cross compiler for ARM64, and Rust with rustup (the Rust of the distributions is too old). NO_INSTALL=1: it never
# installs, it says what's missing.
# One of the two only: NO_RPM=1 or NO_DEB=1. The field Maintainer of the .deb: MAINTAINER="Name <address>".
set -eu

# the oldest Rust that builds the app, the rust-version of Cargo.toml: slice::as_chunks
MIN_RUST=1.88

say() {
    printf '%s\n' "$*" >&2
}

fail() {
    say "$*"
    exit 1
}

has() {
    command -v "$1" >/dev/null 2>&1
}

# a command as root: sudo asks for the password of the user when it needs it
as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif has sudo; then
        sudo "$@"
    else
        fail "sudo isn't installed: run as root: $*"
    fi
}

# major.minor of rustc, empty without it
rust_version() {
    rustc --version 2>/dev/null | sed -n 's/^rustc \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p'
}

# whether the version is MIN_RUST or later
rust_recent() {
    [ -n "$1" ] && [ "$(printf '%s\n%s\n' "$MIN_RUST" "$1" | sort -t. -k1,1n -k2,2n | head -n 1)" = "$MIN_RUST" ]
}

if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    say "Run it without sudo: Rust and the build would belong to root. It uses sudo itself for the packages."
fi

# the package manager of the system: apt for Debian and Ubuntu, dnf for RHEL, its rebuilds and Fedora
if has apt-get; then
    manager=apt
elif has dnf; then
    manager=dnf
else
    manager=none
fi
host=$(uname -m)
TARGET=${TARGET:-}
cross=
case "$TARGET" in
    aarch64-*) [ "$host" = aarch64 ] || cross=aarch64 ;;
    x86_64-*) [ "$host" = x86_64 ] || fail "the packages for x86_64 are built on x86_64" ;;
    "") ;;
    *) fail "no package for $TARGET" ;;
esac

# Rust of rustup first, when it's there
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi
need_rustup=
if ! rust_recent "$(rust_version)" && ! has rustup; then
    need_rustup=1
fi

# what's missing, as packages of the system: a command, then its packages with apt and with dnf ("-": none there)
missing=
want() {
    has "$1" && return 0
    case $manager in
        apt) packages=$2 ;;
        dnf) packages=$3 ;;
        *) packages=$1 ;;
    esac
    if [ "$packages" = - ]; then
        return 0
    fi
    missing="$missing $packages"
}
want cc build-essential gcc
if [ -n "$need_rustup" ]; then
    want curl "curl ca-certificates" "curl ca-certificates"
fi
if [ -z "${NO_DEB:-}" ]; then
    want dpkg-deb dpkg dpkg
fi
if [ -z "${NO_RPM:-}" ]; then
    want rpmbuild rpm rpm-build
fi
if [ -n "$cross" ]; then
    [ "$manager" = apt ] || fail "the packages for ARM64 are built from x86_64 on Debian or Ubuntu, or on ARM64"
    want aarch64-linux-gnu-gcc "gcc-aarch64-linux-gnu libc6-dev-arm64-cross" -
fi

if [ -n "$missing" ]; then
    if [ -n "${NO_INSTALL:-}" ] || [ "$manager" = none ]; then
        fail "missing:$missing"
    fi
    say "installing:$missing"
    case $manager in
        apt)
            as_root apt-get update -q
            # shellcheck disable=SC2086
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $missing
            ;;
        dnf)
            # one at a time: dpkg is only in EPEL on RHEL, the .deb waits without it
            for package in $missing; do
                as_root dnf install -y -q "$package" || say "can't install $package"
            done
            ;;
    esac
fi

has cc || fail "no C compiler: install gcc"
if [ -z "${NO_DEB:-}" ] && ! has dpkg-deb; then
    say "no dpkg-deb: no .deb (on RHEL, dpkg is in EPEL)"
    NO_DEB=1
fi
if [ -z "${NO_RPM:-}" ] && ! has rpmbuild; then
    say "no rpmbuild: no .rpm"
    NO_RPM=1
fi
if [ -n "${NO_DEB:-}" ] && [ -n "${NO_RPM:-}" ]; then
    fail "no package to build"
fi

# Rust: rustup, then the version that builds the app
if [ -n "$need_rustup" ]; then
    [ -z "${NO_INSTALL:-}" ] || fail "Rust $MIN_RUST or later is missing: https://rustup.rs"
    say "installing Rust with rustup, for this user"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    . "$HOME/.cargo/env"
fi
if ! rust_recent "$(rust_version)"; then
    has rustup || fail "Rust $(rust_version) is too old, $MIN_RUST or later builds the app: https://rustup.rs"
    [ -z "${NO_INSTALL:-}" ] || fail "Rust $(rust_version) is too old: rustup update stable"
    rustup update stable --no-self-update
    rustup default stable
fi
TARGET=${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}
if has rustup && ! rustup target list --installed | grep -qx "$TARGET"; then
    rustup target add "$TARGET"
fi
if [ -n "$cross" ]; then
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
fi

root=$(cd "$(dirname "$0")/.." && pwd)
# the names of the app, as the program has them
product_value() {
    sed -n "s/^pub const $1: &str = \"\(.*\)\";/\1/p" "$root/src/product.rs"
}
PRODUCT=$(product_value PRODUCT)
BUNDLE_ID=$(product_value BUNDLE_ID)
LOWER=$(printf '%s' "$PRODUCT" | tr '[:upper:]' '[:lower:]')
EXECUTABLE=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
MAINTAINER=${MAINTAINER:-"$PRODUCT <$LOWER@localhost>"}
case "$TARGET" in
    x86_64-*) DEB_ARCH=amd64; RPM_ARCH=x86_64 ;;
    aarch64-*) DEB_ARCH=arm64; RPM_ARCH=aarch64 ;;
    *) echo "no package for $TARGET" >&2; exit 1 ;;
esac

cargo build --release --target "$TARGET" --manifest-path "$root/Cargo.toml"

work="$root/target/linux-pkg"
rm -rf "$work"
files="$work/files"
mkdir -p "$root/dist"

fill() {
    mkdir -p "$(dirname "$2")"
    sed -e "s|@PRODUCT@|$PRODUCT|g" -e "s|@LOWER@|$LOWER|g" -e "s|@BUNDLE_ID@|$BUNDLE_ID|g" \
        -e "s|@EXECUTABLE@|$EXECUTABLE|g" -e "s|@VERSION@|$VERSION|g" -e "s|@ARCH@|$DEB_ARCH|g" \
        -e "s|@MAINTAINER@|$MAINTAINER|g" "$1" > "$2"
    chmod "${3:-644}" "$2"
}

# the files, as they go on the computer
linux="$root/installer/linux"
install -D -m 755 "$root/target/$TARGET/release/$EXECUTABLE" "$files/usr/bin/$EXECUTABLE"
fill "$linux/authway.service" "$files/usr/lib/systemd/system/$LOWER.service"
fill "$linux/authway.desktop" "$files/usr/share/applications/$LOWER.desktop"
fill "$linux/authway-autostart.desktop" "$files/etc/xdg/autostart/$LOWER.desktop"
fill "$linux/policy.conf" "$files/etc/$LOWER/policy.conf"
fill "$linux/authway.policy" "$files/usr/share/polkit-1/actions/$BUNDLE_ID.policy"
fill "$linux/authway.rules" "$files/usr/share/polkit-1/rules.d/50-$LOWER.rules"
install -D -m 644 "$linux/icons/authway.svg" "$files/usr/share/icons/hicolor/scalable/apps/$LOWER.svg"
for state in idle connected attention refused; do
    install -D -m 644 "$linux/icons/authway-$state.svg" "$files/usr/share/icons/hicolor/scalable/status/$LOWER-$state.svg"
done
install -D -m 644 "$root/LICENSE" "$files/usr/share/doc/$LOWER/copyright"

if [ -z "${NO_DEB:-}" ]; then
    deb="$work/deb"
    cp -a "$files" "$deb"
    SIZE=$(du -sk "$deb" | cut -f1)
    mkdir -p "$deb/DEBIAN"
    fill "$linux/debian/control" "$deb/DEBIAN/control"
    sed -i "s|@SIZE@|$SIZE|" "$deb/DEBIAN/control"
    echo "/etc/$LOWER/policy.conf" > "$deb/DEBIAN/conffiles"
    for script in postinst prerm postrm; do
        fill "$linux/debian/$script" "$deb/DEBIAN/$script" 755
    done
    dpkg-deb --root-owner-group --build "$deb" "$root/dist/${LOWER}_${VERSION}_${DEB_ARCH}.deb"
fi

if [ -z "${NO_RPM:-}" ]; then
    fill "$linux/authway.spec" "$work/$LOWER.spec"
    rpmbuild -bb --target "$RPM_ARCH" --define "_topdir $work/rpm" --define "payload $files" "$work/$LOWER.spec"
    cp "$work/rpm/RPMS/$RPM_ARCH/"*.rpm "$root/dist/"
fi

ls -l "$root/dist"
