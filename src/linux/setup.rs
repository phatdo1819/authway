// Where the packages install the app on Linux, and the steps that need an administrator: pkexec asks for one with a
// window of the desktop, as Windows does with UAC. installer/linux has the .deb and .rpm packages, the unit of
// systemd and the rules of polkit.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::commands;
use crate::log;
use crate::names::{self, PRODUCT};

pub const CANCELLED: &str = "cancelled";

const PKEXEC: &str = "/usr/bin/pkexec";

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn suffix() -> &'static str {
    if cfg!(feature = "testing") {
        " test"
    } else {
        ""
    }
}

fn product() -> String {
    format!("{}{}", PRODUCT.to_lowercase(), suffix())
}

// $XDG_..._HOME, else its default under the home folder
fn xdg(variable: &str, default: &str) -> PathBuf {
    std::env::var_os(variable).map(PathBuf::from).filter(|path| path.is_absolute()).unwrap_or_else(|| home().join(default))
}

// The first of the places where the distributions put a program, None when it isn't installed
pub fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|folder| Path::new(folder).join(name)).find(|path| path.exists())
}

// The tunnels and the device keys, readable by root only. The tests keep everything in the folder of the user.
pub fn support_dir() -> PathBuf {
    if cfg!(feature = "testing") {
        xdg("XDG_DATA_HOME", ".local/share").join(product()).join("service")
    } else {
        PathBuf::from(format!("/var/lib/{}", product()))
    }
}

// readable by the users, as the logs never hold a password, a code or a key
pub fn service_log() -> PathBuf {
    if cfg!(feature = "testing") {
        return support_dir().join("service.log");
    }
    PathBuf::from(format!("/var/log/{}/service.log", product()))
}

pub fn user_data_dir() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config").join(product())
}

pub fn user_log() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state").join(product()).join("client.log")
}

// root, with sudo or a deployment tool: the keyring would be the one of root, not of the user
pub fn is_system_account() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// Runs a program as root: pkexec asks for the password of an administrator. Err(CANCELLED) if the user said no,
// else the error that the program wrote
pub fn run_as_admin(program: &Path, arguments: &[&str]) -> Result<(), String> {
    if !Path::new(PKEXEC).exists() {
        return Err(format!("{} isn't installed: run the same as root, with sudo", PKEXEC));
    }
    let output = Command::new(PKEXEC).arg(program).args(arguments).output().map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    if commands::pkexec_cancelled(output.status.code()) {
        return Err(CANCELLED.to_string());
    }
    let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
    log!("as administrator: {}", error);
    Err(if error.is_empty() { "not allowed".to_string() } else { error })
}

// The users can start the service: a rule of polkit allows it, or polkit asks for an administrator
pub fn start_service() -> Result<(), String> {
    let systemctl = tool("systemctl").ok_or("systemctl isn't installed")?;
    let output = Command::new(systemctl).args(["start", &names::unit_name()]).output().map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
}

// the logs open in the text editor of the desktop
pub fn open_log(path: &Path) {
    let Some(opener) = tool("xdg-open") else {
        log!("xdg-open isn't installed: the log is {}", path.display());
        return;
    };
    if let Err(error) = Command::new(opener).arg(path).spawn() {
        log!("can't open {}: {}", path.display(), error);
    }
}

// --remove-user-data, as the user: the settings, the passwords and the log of the app
pub fn remove_user_data() {
    crate::creds::delete_all();
    crate::settings::delete_user_settings();
    let _ = fs::remove_dir_all(user_data_dir());
    if let Some(folder) = user_log().parent() {
        let _ = fs::remove_dir_all(folder);
    }
}
