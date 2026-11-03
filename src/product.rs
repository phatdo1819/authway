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
pub const MANUFACTURER: &str = "Authway";
// the same for every MSI package of the app, so that a new version replaces the installed one: never change it
pub const UPGRADE_CODE: &str = "{A2E70C27-DA30-4353-A753-EC907223103B}";
// macOS: the identifier of the app, of its package, of the settings of the administrator and, with suffixes, of its
// launchd jobs. The packages stop and remove the jobs of an earlier identifier (remove_other_jobs in
// installer/macos/common.sh), but the settings and the profiles of the administrators don't follow: don't change it
pub const BUNDLE_ID: &str = "io.authway.client";
