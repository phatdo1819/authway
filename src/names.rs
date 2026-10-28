// The names made from the product name: the tests use others, to never touch the installed app

pub use crate::product::*;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn suffix() -> &'static str {
    if cfg!(feature = "testing") {
        " test"
    } else {
        ""
    }
}

// the pipe of the service
pub fn pipe() -> String {
    format!(r"\\.\pipe\{}{}", PRODUCT, suffix())
}

// the tunnels, in HKEY_LOCAL_MACHINE: HKEY_CURRENT_USER for the tests, where the service runs as the user
pub fn tunnels_key() -> String {
    format!(r"SOFTWARE\{}{}\Tunnels", PRODUCT, suffix())
}

pub fn machine_key() -> String {
    format!(r"SOFTWARE\{}{}", PRODUCT, suffix())
}

// the key of the device proof of a tunnel, see device.rs: "Authway device {GUID}" on Windows, a file name on macOS
pub fn device_key(tunnel: &str) -> String {
    format!("{}{} device {}", PRODUCT, suffix(), tunnel)
}

// set by the administrator, in HKEY_LOCAL_MACHINE
pub fn policy_key() -> String {
    format!(r"SOFTWARE\Policies\{}", PRODUCT)
}

// the settings of the user, in HKEY_CURRENT_USER
pub fn user_key() -> String {
    format!(r"Software\{}{}", PRODUCT, suffix())
}

// the passwords in the Credential Manager: "Authway/http://10.103.1.1:8181"
pub fn credential_prefix() -> String {
    format!("{}{}/", PRODUCT, suffix())
}

// the app next to the clock, once per Windows session
pub fn tray_mutex() -> String {
    format!(r"Local\{}{} tray", PRODUCT, suffix())
}

pub fn tray_show_event() -> String {
    format!(r"Local\{}{} show", PRODUCT, suffix())
}

pub fn tray_quit_event() -> String {
    format!(r"Local\{}{} quit", PRODUCT, suffix())
}

pub fn run_value() -> String {
    format!("{}{}", PRODUCT, suffix())
}

// macOS: the socket of the service, in a folder only root can write to, so no other program takes its name
pub fn socket_path() -> String {
    if cfg!(feature = "testing") {
        format!("/tmp/{}-test.sock", PRODUCT.to_lowercase())
    } else {
        format!("/var/run/{}.sock", PRODUCT.to_lowercase())
    }
}

// the launchd jobs: the service, as root, and the app, at every login
pub fn service_label() -> String {
    format!("{}.service", BUNDLE_ID)
}

pub fn agent_label() -> String {
    BUNDLE_ID.to_string()
}
