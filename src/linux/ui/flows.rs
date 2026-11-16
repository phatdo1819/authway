// The steps with questions, the file chooser or the password of an administrator: they run outside of the App,
// which they reach only for a moment, so that the events that the modal dialogs let through find it free. The same
// steps as on macOS; pkexec asks for the administrator.

use std::ffi::c_int;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::gtk::{self, c, g};
use super::{home, quit_main_loop, shutdown, with_app};
use crate::api;
use crate::client::import::{is_taken, load, login_page, name_for, other_name, Duplicate, Login, Ready};
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

// A question or a message, over the main window when it shows: the index of the button chosen, the default one with
// Return; None when the dialog was closed (Esc). The buttons read from the right, the default one there.
pub fn ask(text: &str, detail: Option<&str>, buttons: &[&str], default: usize, warning: bool) -> Option<usize> {
    let g = g();
    unsafe {
        let dialog = (g.gtk_dialog_new)();
        (g.gtk_window_set_title)(dialog, c(PRODUCT).as_ptr());
        (g.gtk_window_set_modal)(dialog, 1);
        (g.gtk_window_set_resizable)(dialog, 0);
        if let Some(parent) = home::parent() {
            (g.gtk_window_set_transient_for)(dialog, parent);
        }
        let row = gtk::hbox(14);
        gtk::margins(row, 16, 18, 8);
        let icon = gtk::image(if warning { "dialog-warning" } else { "dialog-information" }, 48);
        gtk::valign(icon, gtk::ALIGN_START);
        gtk::pack(row, icon, false);
        let texts = gtk::vbox(8);
        let title = gtk::wrapping(text);
        gtk::add_class(title, "authway-heading");
        gtk::pack(texts, title, false);
        if let Some(detail) = detail {
            gtk::pack(texts, gtk::wrapping(detail), false);
        }
        gtk::pack(row, texts, true);
        gtk::pack((g.gtk_dialog_get_content_area)(dialog), row, true);
        for (index, label) in buttons.iter().enumerate().rev() {
            let button = (g.gtk_dialog_add_button)(dialog, c(label).as_ptr(), index as c_int);
            if index == default {
                gtk::add_class(button, "suggested-action");
            }
        }
        (g.gtk_dialog_set_default_response)(dialog, default as c_int);
        let response = (g.gtk_dialog_run)(dialog);
        gtk::destroy(dialog);
        usize::try_from(response).ok().filter(|&index| index < buttons.len())
    }
}

pub fn error_dialog(text: &str) {
    ask(text, None, &["OK"], 0, true);
}

fn choose_file() -> Option<PathBuf> {
    let g = g();
    unsafe {
        let parent = home::parent().unwrap_or(std::ptr::null_mut());
        let chooser = (g.gtk_file_chooser_native_new)(
            c(strings::IMPORT_TITLE).as_ptr(),
            parent,
            gtk::FILE_CHOOSER_OPEN,
            std::ptr::null(),
            std::ptr::null(),
        );
        // "VPN configuration (*.conf)|*.conf|All files (*.*)|*.*": a name and its patterns, two at a time
        let parts: Vec<&str> = strings::IMPORT_FILTER.split('|').collect();
        for pair in parts.chunks(2) {
            let [name, patterns] = pair else { continue };
            let filter = (g.gtk_file_filter_new)();
            (g.gtk_file_filter_set_name)(filter, c(name).as_ptr());
            for pattern in patterns.split(';') {
                (g.gtk_file_filter_add_pattern)(filter, c(if pattern == "*.*" { "*" } else { pattern }).as_ptr());
            }
            (g.gtk_file_chooser_add_filter)(chooser, filter);
        }
        let response = (g.gtk_native_dialog_run)(chooser);
        let path = if response == gtk::RESPONSE_ACCEPT {
            let name = (g.gtk_file_chooser_get_filename)(chooser);
            let path = gtk::text_of(name);
            if !name.is_null() {
                (g.g_free)(name as *mut std::ffi::c_void);
            }
            (!path.is_empty()).then(|| PathBuf::from(path))
        } else {
            None
        };
        (g.g_object_unref)(chooser);
        path
    }
}

pub fn import_from_file() {
    if let Some(path) = choose_file() {
        import_path(&path);
    }
    home::refresh();
}

// The configuration for the import as root, in the temporary folder: root reads it there
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

pub fn import_path(path: &Path) {
    let (text, config) = match load(path) {
        Ok(loaded) => loaded,
        Err(message) => return error_dialog(&message),
    };
    let mut name = name_for(&config, path);
    let mut replace = false;
    let known = with_app(|app| app.tunnel_names()).unwrap_or_default();
    if is_taken(&name, &known) {
        let other = other_name(&name, &known);
        match duplicate_dialog(&name, &other) {
            Duplicate::KeepBoth => name = other,
            Duplicate::Replace => replace = true,
            Duplicate::Cancel => return,
        }
    }
    match ipc::call(&Request::Import { name: name.clone(), config: text.clone(), replace }) {
        Ok(response) if response.ok => {}
        // the same steps, as administrator
        Ok(response) if response.error_code() == ipc::ACCESS_DENIED => match import_as_admin(&text, &name, replace) {
            Ok(()) => {}
            Err(error) if error == CANCELLED => return,
            Err(error) => return error_dialog(&error),
        },
        Ok(response) => return error_dialog(&strings::import_invalid(response.message())),
        Err(error) => return error_dialog(&call_text(&error)),
    }
    log!("{}: added from {}", name, path.display());
    with_app(|app| app.list_soon());
    let file = path.file_name().map(|file| file.to_string_lossy().to_string()).unwrap_or_default();
    let ready = ready_dialog(&name, &file);
    if ready.deletes() {
        if let Err(error) = fs::remove_file(path) {
            log!("can't delete {}: {}", path.display(), error);
            ask(&strings::import_not_deleted(&file, &error.to_string()), None, &["OK"], 0, true);
        }
    }
    if ready.connects() {
        with_app(|app| app.connect(&name));
    }
}

// "There's already a VPN named Office": keep both (the default, Return: nothing is lost), replace it, or Cancel (Esc)
fn duplicate_dialog(name: &str, other: &str) -> Duplicate {
    let detail = format!("{}\n\n{}", strings::import_exists_note(name), strings::import_exists_choices(name, other));
    let buttons = [strings::IMPORT_KEEP_BOTH, strings::REPLACE, strings::CANCEL];
    match ask(&strings::import_exists(name), Some(&detail), &buttons, 0, true) {
        Some(0) => Duplicate::KeepBoth,
        Some(1) => Duplicate::Replace,
        _ => Duplicate::Cancel,
    }
}

// "Office is ready", and three buttons: connect and delete the file (the default, Return), connect and keep it, not
// now (Esc)
fn ready_dialog(name: &str, file: &str) -> Ready {
    let detail = format!("{}\n\n{}", strings::IMPORT_SAVED, strings::import_file_note(file));
    let buttons = [strings::IMPORT_CONNECT_DELETE, strings::IMPORT_CONNECT_KEEP, strings::IMPORT_LATER];
    match ask(&strings::import_ready(name), Some(&detail), &buttons, 0, false) {
        Some(0) => Ready::ConnectAndDelete,
        Some(1) => Ready::Connect,
        _ => Ready::Later,
    }
}

// --import <file> --name <name> [--replace], as root with sudo or pkexec. With [--username <username> [--password
// <password>]], as the user of the VPN, without sudo: the login goes in their keyring, and only the import asks for an
// administrator, when they aren't allowed
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

pub fn remove(name: &str) {
    if ask(&strings::remove_confirm(name), None, &[strings::REMOVE, strings::CANCEL], 1, true) != Some(0) {
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
                Err(error) => return error_dialog(&error.to_string()),
            };
            match setup::run_as_admin(&exe, &["--remove", name]) {
                Ok(()) => {}
                Err(error) if error == CANCELLED => return,
                Err(error) => return error_dialog(&error),
            }
        }
        Ok(response) => return error_dialog(response.message()),
        Err(error) => return error_dialog(&call_text(&error)),
    }
    with_app(|app| app.removed(name));
}

// While the VPN is off; pkexec asks for an administrator when the user isn't allowed. True when it's done
pub fn rename(name: &str, new_name: &str) -> bool {
    match ipc::call(&Request::Rename { name: name.to_string(), new_name: new_name.to_string() }) {
        Ok(response) if response.ok => {}
        Ok(response) if response.error_code() == ipc::ACCESS_DENIED => {
            let exe = match std::env::current_exe() {
                Ok(exe) => exe,
                Err(error) => {
                    error_dialog(&error.to_string());
                    return false;
                }
            };
            match setup::run_as_admin(&exe, &["--rename", name, "--to", new_name]) {
                Ok(()) => {}
                Err(error) if error == CANCELLED => return false,
                Err(error) => {
                    error_dialog(&strings::rename_failed(&error));
                    return false;
                }
            }
        }
        Ok(response) => {
            error_dialog(&strings::rename_failed(response.message()));
            return false;
        }
        Err(error) => {
            error_dialog(&call_text(&error));
            return false;
        }
    }
    log!("{}: renamed {}", name, new_name);
    with_app(|app| app.renamed(name, new_name));
    true
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
    shutdown();
}

// Quit by the user, after a confirmation: the tunnels stay off at the next start. At the logout they come back on
pub fn quit(by_user: bool) {
    let active = with_app(|app| app.active_tunnels()).unwrap_or_default();
    if by_user && !active.is_empty() && ask(&strings::quit_confirm(), None, &[strings::MENU_QUIT, strings::CANCEL], 1, true) != Some(0) {
        return;
    }
    if by_user {
        with_app(|app| app.forget_reconnect());
    }
    stop_tunnels();
    quit_main_loop();
}
