# Building

The names of the app are in [src/product.rs](../src/product.rs), and the name of the exe in
[Cargo.toml](../Cargo.toml): to rename the app, change them there.

The packages of the [releases](https://github.com/phatdo1819/authway/releases) are the files built below, without
certificates, with `-unsigned` added to their names.

## Windows

You need:

- Rust stable with the MSVC toolchain: Visual Studio or its Build Tools, with the Windows SDK;
- [WiX Toolset 3.14](https://github.com/wixtoolset/wix3/releases).

```
rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc
powershell -File tools\fetch-wireguard.ps1     # wireguard.dll for x64 and ARM64, checked
powershell -File tools\dist.ps1                # dist\authway-<version>-x64.msi and -arm64.msi
```

- `dist.ps1` finds WiX through `%WIX%`, or `-Wix <its bin folder>`. It takes the names from `src\product.rs` and the
  version from `Cargo.toml`: change them there, never in the `.wxs`.
- Never change `UPGRADE_CODE`, or a new version won't replace the installed one.
- `tools\make-icons.cmd` draws the icons in `assets\` and the pictures of the setup again, with the C# compiler of
  Windows.

## macOS

You need the Command Line Tools of Xcode, Rust, and Go 1.23.1 or later.

```
rustup target add aarch64-apple-darwin x86_64-apple-darwin
tools/fetch-wireguard-go.sh      # wireguard-go from its source, checked, for both processors
tools/dist-macos.sh              # dist/authway-<version>-macos.pkg
```

- The package needs macOS 15 or later, the versions Apple still updates. The code was written for macOS 11 and
  later but never tested there: to build for an older macOS, change the minimum in
  `installer/macos/Distribution.xml`, `installer/macos/Info.plist` and `MACOSX_DEPLOYMENT_TARGET` in
  `tools/dist-macos.sh`.
- The package is signed ad hoc, which is enough for the Mac that builds it.
- For other Macs, sign it with the certificates of an Apple developer account and notarize it, or Gatekeeper refuses
  it: `SIGN_APP="Developer ID Application: ..."` and `SIGN_PKG="Developer ID Installer: ..."`.
- With ad-hoc signatures, macOS can ask again for the saved passwords after an update: the keychain knows the app by
  its signature.

## Linux

On Debian, Ubuntu, RHEL or Fedora, as a normal user. The script installs what's missing, with sudo: gcc for the
linker, `dpkg-deb` and `rpmbuild` (the package `rpm` on Debian and Ubuntu), the cross compiler for ARM64, and Rust
1.88 or later with rustup, for the user (the Rust of the distributions is too old). No development files of GTK: the
app loads it when it starts.

```
tools/dist-linux.sh     # dist/authway_<version>_amd64.deb and dist/authway-<version>-1.x86_64.rpm
```

- `NO_INSTALL=1 tools/dist-linux.sh` installs nothing and says what's missing.
- On RHEL, `dpkg` is only in EPEL: without it, the script builds the .rpm alone.
- Build the releases on RHEL 9 or Rocky Linux 9, with EPEL for the .deb (a container is enough, as in the
  [CI](../.github/workflows/ci.yml)): a program needs the glibc of the system that builds it, or a later one, and RHEL
  9 has the oldest of the systems of the packages, 2.34 (Ubuntu 22.04: 2.35, Debian 12: 2.36). The script says the
  version the packages need, and warns when it's later than 2.34.
- For ARM64: `TARGET=aarch64-unknown-linux-gnu tools/dist-linux.sh`, on ARM64, or from x86_64 on Debian or Ubuntu,
  where the script installs the cross compiler and sets it as the linker.
- The field Maintainer of the .deb: `MAINTAINER="Name <address>" tools/dist-linux.sh`.
- From Windows or macOS, `cargo clippy --target x86_64-unknown-linux-gnu --all-targets` checks the Linux code, and
  `cargo test` runs the tests of [commands.rs](../src/linux/commands.rs) there too.

## Tests

```
cargo test --features testing
```

The `testing` feature makes a build for the tests only. Its service runs as the user (`--service-console`) with fake
tunnels, and its own pipe or socket, keys and credentials, so it never touches an installed app. On macOS, the login
test on `127.0.0.2` needs `sudo ifconfig lo0 alias 127.0.0.2` first.

What the tests check: [What was tested](testing.md).

## The licenses in the packages

- Authway: the MIT license of [LICENSE](../LICENSE), installed as `LICENSE.txt`.
- `wireguard.dll`: the license of WireGuard LLC, installed as `wireguard-LICENSE.txt`. It allows shipping the DLL
  unchanged next to an app that uses its API.
- `wireguard-go`: the MIT license, installed as `wireguard-go-LICENSE.txt` on macOS.
