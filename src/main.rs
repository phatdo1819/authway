#![windows_subsystem = "windows"]

use std::path::PathBuf;

use authway::client::import::Login;
use authway::ui::{self, flows, Startup};
#[cfg(windows)]
use authway::log;
use authway::setup;

// the value of an option: --name "Road warriors", or --name="Road warriors" as OpenVPN Connect writes them
fn value(arguments: &[String], option: &str) -> Option<String> {
    let joined = format!("{}=", option);
    arguments.iter().enumerate().find_map(|(index, argument)| match argument.strip_prefix(&joined) {
        Some(value) => Some(value.to_string()),
        None if argument == option => arguments.get(index + 1).cloned(),
        None => None,
    })
}

// --username <username> [--password <password>]: Err without a username, or with an empty one
fn login(arguments: &[String]) -> Result<Option<Login>, ()> {
    match (value(arguments, "--username"), value(arguments, "--password")) {
        (None, None) => Ok(None),
        (Some(username), password) if !username.is_empty() => Ok(Some(Login { username, password })),
        _ => Err(()),
    }
}

// a step of the setup, as SYSTEM, which logs next to the service
#[cfg(windows)]
fn setup_step(step: fn()) -> i32 {
    log::init(setup::install_dir().join("log").join("setup.log"));
    step();
    0
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let has = |option: &str| arguments.iter().any(|argument| argument == option);
    let code = match arguments.first().map(String::as_str) {
        // started by the service manager, or launchd
        Some("--service") => authway::service::run(),
        #[cfg(feature = "testing")]
        Some("--service-console") => authway::service::run_console(),
        // run by the MSI package, see setup.rs
        #[cfg(windows)]
        Some("--msi-stop-apps") => setup_step(setup::stop_apps),
        #[cfg(windows)]
        Some("--msi-start-apps") => setup_step(setup::start_apps),
        #[cfg(windows)]
        Some("--msi-remove-data") => {
            setup::remove_data();
            0
        }
        #[cfg(windows)]
        Some("--msi-remove-user-data") => {
            setup::remove_user_data();
            0
        }
        // run by uninstall.sh as each user
        #[cfg(target_os = "macos")]
        Some("--remove-user-data") => {
            setup::remove_user_data();
            0
        }
        // as administrator
        Some("--import") => match (arguments.get(1), value(&arguments, "--name"), login(&arguments)) {
            (Some(path), Some(name), Ok(login)) => {
                flows::import_command(&PathBuf::from(path), &name, has("--replace"), login.as_ref())
            }
            _ => 2,
        },
        Some("--remove") => match arguments.get(1) {
            Some(name) => flows::remove_command(name),
            None => 2,
        },
        Some("--rename") => match (arguments.get(1), value(&arguments, "--to")) {
            (Some(name), Some(new_name)) => flows::rename_command(name, &new_name),
            _ => 2,
        },
        #[cfg(windows)]
        Some("--quit") => flows::quit_command(),
        // at every sign-in, and after the setup
        Some("--startup") => ui::run(Startup::SignIn),
        _ => ui::run(Startup::Normal),
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(text: &[&str]) -> Vec<String> {
        text.iter().map(|argument| argument.to_string()).collect()
    }

    #[test]
    fn options() {
        let given = arguments(&["--import", "office.conf", "--name", "Office", "--username=alice", "--password", "a=b c"]);
        assert_eq!(value(&given, "--name").as_deref(), Some("Office"));
        let given = login(&given).unwrap().unwrap();
        assert_eq!((given.username.as_str(), given.password.as_deref()), ("alice", Some("a=b c")));
        // the username alone, to fill only it
        let given = login(&arguments(&["--username", "alice"])).unwrap().unwrap();
        assert_eq!(given.password, None);
        assert!(login(&arguments(&["--name", "Office"])).unwrap().is_none());
        // a password for nobody, or an empty username
        assert!(login(&arguments(&["--password", "x"])).is_err());
        assert!(login(&arguments(&["--username=", "--password", "x"])).is_err());
        assert_eq!(value(&arguments(&["--rename", "Office", "--to", "Work"]), "--to").as_deref(), Some("Work"));
    }
}
