// Where the package installs the app on macOS, and the steps that need an administrator: macOS asks for one with
// its own window, as Windows does with UAC. installer/macos has the package and uninstall.sh.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::log;
use crate::names::{self, PRODUCT};

pub const CANCELLED: &str = "cancelled";

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

// the app of the users
pub fn app_path() -> PathBuf {
    PathBuf::from(format!("/Applications/{}.app", PRODUCT))
}

pub fn app_exe() -> PathBuf {
    app_path().join("Contents/MacOS").join(PRODUCT.to_lowercase())
}

// The service and wireguard-go, with the tunnels: only root can change this folder, unlike /Applications where an
// administrator could replace the app without a password. The tests keep everything in the folder of the user.
pub fn support_dir() -> PathBuf {
    if cfg!(feature = "testing") {
        home().join(format!("Library/Application Support/{}{}/service", PRODUCT, suffix()))
    } else {
        PathBuf::from(format!("/Library/Application Support/{}", PRODUCT))
    }
}

pub fn wireguard_go() -> PathBuf {
    if cfg!(feature = "testing") {
        let exe = std::env::current_exe().unwrap_or_default();
        return exe.parent().map(Path::to_path_buf).unwrap_or_default().join("wireguard-go");
    }
    support_dir().join("wireguard-go")
}

pub fn service_log() -> PathBuf {
    if cfg!(feature = "testing") {
        return support_dir().join("service.log");
    }
    PathBuf::from(format!("/Library/Logs/{}/service.log", PRODUCT))
}

pub fn user_data_dir() -> PathBuf {
    home().join(format!("Library/Application Support/{}{}", PRODUCT, suffix()))
}

pub fn user_log() -> PathBuf {
    if cfg!(feature = "testing") {
        return user_data_dir().join("client.log");
    }
    home().join(format!("Library/Logs/{}/client.log", PRODUCT))
}

pub fn is_installed_copy() -> bool {
    let exe = std::env::current_exe().and_then(fs::canonicalize).unwrap_or_default();
    fs::canonicalize(app_exe()).is_ok_and(|installed| installed == exe)
}

// 'it'\''s' for /bin/sh
fn shell_quote(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', r"'\''"))
}

// "..." for AppleScript
fn applescript_quote(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', r"\\").replace('"', "\\\""))
}

// Runs a program as root: macOS asks for the name and password of an administrator. Err(CANCELLED) if the user
// said no, else the error that the program wrote
pub fn run_as_admin(program: &Path, arguments: &[&str]) -> Result<(), String> {
    let mut command = shell_quote(&program.display().to_string());
    for argument in arguments {
        command.push(' ');
        command.push_str(&shell_quote(argument));
    }
    let script = format!(
        "do shell script {} with prompt {} with administrator privileges",
        applescript_quote(&command),
        applescript_quote(&format!("{} wants to change the VPNs of this Mac.", PRODUCT))
    );
    let output = Command::new("/usr/bin/osascript").args(["-e", &script]).output().map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let error = String::from_utf8_lossy(&output.stderr);
    // -128: the user cancelled
    if error.contains("(-128)") {
        return Err(CANCELLED.to_string());
    }
    log!("as administrator: {}", error.trim());
    Err(script_error(&error))
}

// "0:120: execution error: <what the program wrote> (1)"
fn script_error(error: &str) -> String {
    let text = error.split_once("execution error: ").map_or(error, |(_, rest)| rest).trim();
    let text = match text.rsplit_once(" (") {
        Some((message, code)) if code.trim_end_matches(')').parse::<i32>().is_ok() => message,
        _ => text,
    };
    text.trim().to_string()
}

// the service is a launchd job that starts with the Mac; root starts it again
pub fn start_service() -> Result<(), String> {
    let target = format!("system/{}", names::service_label());
    run_as_admin(Path::new("/bin/launchctl"), &["kickstart", "-k", &target])
}

// the logs open in Console
pub fn open_log(path: &Path) {
    if let Err(error) = Command::new("/usr/bin/open").arg("-a").arg("Console").arg(path).spawn() {
        log!("can't open {}: {}", path.display(), error);
    }
}

// --remove-user-data, as each user, by uninstall.sh: the settings, the passwords and the log of the app
pub fn remove_user_data() {
    crate::creds::delete_all();
    crate::settings::delete_user_settings();
    let _ = fs::remove_dir_all(user_data_dir());
    if let Some(folder) = user_log().parent() {
        let _ = fs::remove_dir_all(folder);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(applescript_quote(r#"say "hi" \o/"#), r#""say \"hi\" \\o/""#);
    }

    #[test]
    fn errors_of_scripts() {
        assert_eq!(script_error("0:120: execution error: There's no VPN named Home. (1)\n"), "There's no VPN named Home.");
        assert_eq!(script_error("something else"), "something else");
    }
}
