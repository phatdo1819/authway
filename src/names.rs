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
