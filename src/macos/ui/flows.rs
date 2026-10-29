// The steps with alerts, the file panel or the password of an administrator: they run outside of the App, which
// they reach only for a moment, so that the events that the modal windows let through find it free

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use objc2::MainThreadMarker;
use objc2_app_kit::{NSAlert, NSAlertStyle, NSApplication, NSControlStateValueOn, NSModalResponseOK, NSOpenPanel};
use objc2_foundation::NSArray;
use objc2_uniform_type_identifiers::UTType;

use super::{activate, alert, error_alert, ns, with_app};
use crate::api;
use crate::client::import::{load, login_page, name_for, Login};
use crate::creds;
use crate::ipc::{self, CallError, Request};
use crate::log;
use crate::names::PRODUCT;
use crate::setup::{self, CANCELLED};
use crate::strings;

const QUIT_LOGOUT_TIMEOUT: Duration = Duration::from_secs(2);

fn call_text(error: &CallError) -> String {
    match error {
        CallError::Unavailable => strings::service_unavailable(),
        CallError::Failed(message) => message.clone(),
    }
}

// A copy of the app out of /Applications: the installed one starts instead, if there is one
pub fn start_installed(mtm: MainThreadMarker) -> i32 {
    if setup::app_exe().exists() && Command::new("/usr/bin/open").arg(setup::app_path()).status().is_ok_and(|status| status.success()) {
        return 0;
    }
    alert(mtm, &strings::not_installed(), None, NSAlertStyle::Informational, &["OK"]);
    1
}

fn choose_file(mtm: MainThreadMarker) -> Option<PathBuf> {
    activate(mtm);
    let panel = NSOpenPanel::openPanel(mtm);
    panel.setTitle(Some(&ns(strings::IMPORT_TITLE)));
    panel.setMessage(Some(&ns(strings::IMPORT_TITLE)));
    panel.setCanChooseDirectories(false);
    panel.setAllowsMultipleSelection(false);
    let types: Vec<_> = ["conf", "txt"].iter().filter_map(|extension| UTType::typeWithFilenameExtension(&ns(extension))).collect();
    if !types.is_empty() {
        panel.setAllowedContentTypes(&NSArray::from_retained_slice(&types));
    }
    if panel.runModal() != NSModalResponseOK {
        return None;
    }
    panel.URL().and_then(|url| url.path()).map(|path| PathBuf::from(path.to_string()))
}

pub fn import_from_file(mtm: MainThreadMarker) {
    if let Some(path) = choose_file(mtm) {
        import_path(mtm, &path);
    }
}

// The configuration for the import as root, in the temporary folder of the user: root can read it there, not
// always in the folders that macOS protects, like Downloads
fn private_copy(text: &str) -> Result<PathBuf, String> {
    let path = std::env::temp_dir().join(format!("{}-{}.conf", PRODUCT.to_lowercase(), std::process::id()));
    let _ = fs::remove_file(&path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("can't write {}: {}", path.display(), error))?;
    file.write_all(text.as_bytes()).map_err(|error| format!("can't write {}: {}", path.display(), error))?;
    Ok(path)
}

fn import_as_admin(text: &str, name: &str, replace: bool) -> Result<(), String> {
    let copy = private_copy(text)?;
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let copy_text = copy.display().to_string();
    let mut arguments = vec!["--import", &copy_text, "--name", name];
    if replace {
        arguments.push("--replace");
    }
    let result = setup::run_as_admin(&exe, &arguments);
    let _ = fs::remove_file(&copy);
    result
}

pub fn import_path(mtm: MainThreadMarker, path: &Path) {
    let (text, config) = match load(path) {
        Ok(loaded) => loaded,
        Err(message) => return error_alert(mtm, &message),
    };
    let name = name_for(&config, path);
    let known = with_app(|app| app.tunnel_names()).unwrap_or_default();
    let replace = known.iter().any(|known| known.eq_ignore_ascii_case(&name));
    if replace
        && alert(mtm, &strings::import_exists(&name), None, NSAlertStyle::Warning, &[strings::REPLACE, strings::CANCEL]) != 0
    {
        return;
    }
    match ipc::call(&Request::Import { name: name.clone(), config: text.clone(), replace }) {
        Ok(response) if response.ok => {}
        // the same steps, as administrator
        Ok(response) if response.error_code() == ipc::ACCESS_DENIED => match import_as_admin(&text, &name, replace) {
            Ok(()) => {}
            Err(error) if error == CANCELLED => return,
            Err(error) => return error_alert(mtm, &error),
        },
        Ok(response) => return error_alert(mtm, &strings::import_invalid(response.message())),
        Err(error) => return error_alert(mtm, &call_text(&error)),
    }
    log!("{}: added from {}", name, path.display());
    with_app(|app| app.list_soon());
    let file = path.file_name().map(|file| file.to_string_lossy().to_string()).unwrap_or_default();
    let (connect, delete) = ready_dialog(mtm, &name, &file);
    if delete {
        if let Err(error) = fs::remove_file(path) {
            log!("can't delete {}: {}", path.display(), error);
        }
    }
    if connect {
        with_app(|app| app.connect(&name));
    }
}

// "Office is ready": connect now or later, and delete the file, checked
fn ready_dialog(mtm: MainThreadMarker, name: &str, file: &str) -> (bool, bool) {
    activate(mtm);
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&ns(&strings::import_ready(name)));
    alert.setInformativeText(&ns(strings::IMPORT_SAVED));
    alert.setAlertStyle(NSAlertStyle::Informational);
    alert.addButtonWithTitle(&ns(strings::IMPORT_CONNECT));
    alert.addButtonWithTitle(&ns(strings::IMPORT_LATER));
    alert.setShowsSuppressionButton(true);
    let delete = alert.suppressionButton();
    if let Some(button) = &delete {
        button.setTitle(&ns(&strings::import_delete_file(file)));
        button.setState(NSControlStateValueOn);
    }
    let connect = alert.runModal() == objc2_app_kit::NSAlertFirstButtonReturn;
    (connect, delete.is_some_and(|button| button.state() == NSControlStateValueOn))
}

// --import <file> --name <name> [--replace], as root: the errors go to the app through osascript. With
// [--username <username> [--password <password>]], as the user of the VPN, without sudo: the login goes in their
// keychain, and only the import asks for an administrator, when they aren't allowed
pub fn import_command(path: &Path, name: &str, replace: bool, login: Option<&Login>) -> i32 {
    let fail = |message: &str| {
        eprintln!("{}", message);
        1
    };
    let (text, config) = match load(path) {
        Ok(loaded) => loaded,
        Err(message) => return fail(&message),
    };
    let page = match login {
        Some(_) if setup::is_system_account() => return fail(strings::IMPORT_LOGIN_SYSTEM),
        Some(login) => match login_page(&config, login) {
            Ok(page) => Some(page),
            Err(message) => return fail(&message),
        },
        None => None,
    };
    match ipc::call(&Request::Import { name: name.to_string(), config: text.clone(), replace }) {
        Ok(response) if response.ok => {}
        Ok(response) if response.error_code() == ipc::ACCESS_DENIED && login.is_some() => {
            match import_as_admin(&text, name, replace) {
                Ok(()) => {}
                Err(error) if error == CANCELLED => return 1,
                Err(error) => return fail(&error),
            }
        }
        Ok(response) => return fail(&strings::import_invalid(response.message())),
        Err(error) => return fail(&call_text(&error)),
    }
    if let (Some(page), Some(login)) = (page, login) {
        if !creds::save(&page, &login.username, login.password.as_deref()) {
            return fail(&strings::import_login_not_saved(name, creds::STORE_NAME));
        }
        log!("{}: login of {} saved from the command line", name, login.username);
    }
    0
}

pub fn remove(mtm: MainThreadMarker, name: &str) {
    let answer = alert(mtm, &strings::remove_confirm(name), None, NSAlertStyle::Warning, &[strings::REMOVE, strings::CANCEL]);
    if answer != 0 {
        return;
    }
    if let Some(Some((page, interface))) = with_app(|app| app.release(name)) {
        api::logout(&page, interface, Some(QUIT_LOGOUT_TIMEOUT));
    }
    match ipc::call(&Request::Remove { name: name.to_string() }) {
        Ok(response) if response.ok => {}
        Ok(response) if response.error_code() == ipc::ACCESS_DENIED => {
            let exe = match std::env::current_exe() {
                Ok(exe) => exe,
                Err(error) => return error_alert(mtm, &error.to_string()),
            };
            match setup::run_as_admin(&exe, &["--remove", name]) {
                Ok(()) => {}
                Err(error) if error == CANCELLED => return,
                Err(error) => return error_alert(mtm, &error),
            }
        }
        Ok(response) => return error_alert(mtm, response.message()),
        Err(error) => return error_alert(mtm, &call_text(&error)),
    }
    with_app(|app| app.removed(name));
}

// --remove <name>, as root
pub fn remove_command(name: &str) -> i32 {
    match ipc::call(&Request::Remove { name: name.to_string() }) {
        Ok(response) if response.ok => 0,
        Ok(response) => {
            eprintln!("{}", response.message());
            1
        }
        Err(error) => {
            eprintln!("{}", call_text(&error));
            1
        }
    }
}

// --rename <name> --to <new name>, as root
pub fn rename_command(name: &str, new_name: &str) -> i32 {
    match ipc::call(&Request::Rename { name: name.to_string(), new_name: new_name.to_string() }) {
        Ok(response) if response.ok => 0,
        Ok(response) => {
            eprintln!("{}", response.message());
            1
        }
        Err(error) => {
            eprintln!("{}", call_text(&error));
            1
        }
    }
}

// The tunnels go off with the app: nobody would watch their session anymore
pub fn stop_tunnels() {
    let active = with_app(|app| app.active_tunnels()).unwrap_or_default();
    for (name, session_page) in active {
        if let Some((page, interface)) = session_page {
            api::logout(&page, interface, Some(QUIT_LOGOUT_TIMEOUT));
        }
        if let Err(error) = ipc::call(&Request::Down { name: name.clone() }) {
            log!("{}: can't disconnect: {}", name, error);
        }
    }
    super::shutdown();
}

pub fn quit(mtm: MainThreadMarker, confirm: bool) {
    let active = with_app(|app| app.active_tunnels()).unwrap_or_default();
    if confirm
        && !active.is_empty()
        && alert(mtm, &strings::quit_confirm(), None, NSAlertStyle::Warning, &[strings::MENU_QUIT, strings::CANCEL]) != 0
    {
        return;
    }
    stop_tunnels();
    NSApplication::sharedApplication(mtm).terminate(None);
}
