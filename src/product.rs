// The names of the app, in one place to rename it: build.rs, tools\dist.ps1 for the MSI package and
// tools/dist-macos.sh for the macOS package read this file too. The exe takes the name of the package in
// Cargo.toml, keep EXE_NAME the same.

pub const PRODUCT: &str = "Authway";
pub const EXE_NAME: &str = "authway.exe";
// the Windows service that owns the tunnels
pub const SERVICE_NAME: &str = "Authway";
pub const SERVICE_DISPLAY_NAME: &str = "Authway tunnels";
pub const SERVICE_DESCRIPTION: &str = "Connects and disconnects the VPN tunnels of Authway.";
// the publisher, in the installed apps and in the properties of the exe
pub const MANUFACTURER: &str = "phatdo1819";
// the same for every MSI package of the app, so that a new version replaces the installed one: never change it
pub const UPGRADE_CODE: &str = "{A2E70C27-DA30-4353-A753-EC907223103B}";
// macOS: the identifier of the app, of its package and, with suffixes, of its launchd jobs: never change it either
pub const BUNDLE_ID: &str = "io.github.phatdo1819.authway";
