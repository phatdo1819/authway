#![windows_subsystem = "windows"]

use std::path::PathBuf;

use authway::ui::{self, flows, Startup};
#[cfg(windows)]
use authway::log;
use authway::setup;

// the value after an option: --name "Road warriors"
fn value(arguments: &[String], option: &str) -> Option<String> {
    let index = arguments.iter().position(|argument| argument == option)?;
    arguments.get(index + 1).cloned()
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
        Some("--import") => match (arguments.get(1), value(&arguments, "--name")) {
            (Some(path), Some(name)) => flows::import_command(&PathBuf::from(path), &name, has("--replace")),
            _ => 2,
        },
        Some("--remove") => match arguments.get(1) {
            Some(name) => flows::remove_command(name),
            None => 2,
        },
        #[cfg(windows)]
        Some("--quit") => flows::quit_command(),
        // at every sign-in, and after the setup
        Some("--startup") => ui::run(Startup::SignIn),
        _ => ui::run(Startup::Normal),
    };
    std::process::exit(code);
}
