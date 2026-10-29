// The steps with message boxes, file dialogs or UAC: they run outside of the App, which they reach only for a
// moment, so that the messages pumped by the dialogs find it free

use std::fs;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Controls::{
    TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOG_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION, TDF_VERIFICATION_FLAG_CHECKED,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    PostQuitMessage, IDYES, MB_DEFBUTTON2, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION, MB_ICONWARNING, MB_OK,
    MB_YESNO,
};

use super::tray::{running, signal, with_app};
use super::{instance, message_box};
use crate::api;
use crate::client::import::{load, login_page, name_for, Login};
use crate::creds;
use crate::ipc::{self, CallError, Request};
use crate::log;
use crate::names;
use crate::setup::{self, quote, CANCELLED};
use crate::strings;
use crate::win::wide;

const QUIT_LOGOUT_TIMEOUT: Duration = Duration::from_secs(2);
// the logouts and the tunnels off, before the app quits
const QUIT_WAIT: Duration = Duration::from_secs(15);
const BUTTON_CONNECT: i32 = 100;
const BUTTON_CLOSE: i32 = 101;

fn error_box(owner: HWND, text: &str) {
    message_box(owner, text, MB_OK | MB_ICONERROR);
}

fn call_text(error: &CallError) -> String {
    match error {
        CallError::Unavailable => strings::service_unavailable(),
        CallError::Failed(message) => message.clone(),
    }
}

// An exe out of the folder of the MSI package: the installed app starts instead, if there is one
pub fn start_installed() -> i32 {
    let installed = setup::installed_exe();
    if installed.exists() && setup::launch(&installed, "") {
        return 0;
    }
    message_box(ptr::null_mut(), &strings::not_installed(), MB_OK | MB_ICONINFORMATION);
    1
}

// --quit: the app of this session quits, and this waits until it has, for the setup
pub fn quit_command() -> i32 {
    if !signal(&names::tray_quit_event()) {
        return 1;
    }
    let deadline = Instant::now() + QUIT_WAIT;
    while running() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    0
}

fn choose_file(owner: HWND) -> Option<PathBuf> {
    let filter: Vec<u16> = strings::IMPORT_FILTER.replace('|', "\0").encode_utf16().chain([0, 0]).collect();
    let title = wide(strings::IMPORT_TITLE);
    let mut file = vec![0u16; 1024];
    let mut dialog: OPENFILENAMEW = unsafe { zeroed() };
    dialog.lStructSize = size_of::<OPENFILENAMEW>() as u32;
    dialog.hwndOwner = owner;
    dialog.hInstance = instance();
    dialog.lpstrFilter = filter.as_ptr();
    dialog.nFilterIndex = 1;
    dialog.lpstrFile = file.as_mut_ptr();
    dialog.nMaxFile = file.len() as u32;
    dialog.lpstrTitle = title.as_ptr();
    dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
        return None;
    }
    Some(crate::win::path_from_wide(&file))
}

pub fn import_from_file(owner: HWND) {
    if let Some(path) = choose_file(owner) {
        import_path(owner, &path);
    }
}

pub fn import_path(owner: HWND, path: &Path) {
    let (text, config) = match load(path) {
        Ok(loaded) => loaded,
        Err(message) => return error_box(owner, &message),
    };
    let name = name_for(&config, path);
    let known = with_app(|app| app.tunnel_names()).unwrap_or_default();
    let replace = known.iter().any(|known| known.eq_ignore_ascii_case(&name));
    if replace && message_box(owner, &strings::import_exists(&name), MB_YESNO | MB_ICONQUESTION) != IDYES {
        return;
    }
    let request = Request::Import { name: name.clone(), config: text, replace };
    match ipc::call(&request) {
        Ok(response) if response.ok => {}
        Ok(response) if response.error_code() == ipc::ACCESS_DENIED => {
            // the same steps, as administrator
            match setup::elevate(&admin_import(path, &name, replace), owner) {
                Ok(0) => {}
                Ok(_) => return,
                Err(error) if error == CANCELLED => return,
                Err(error) => return error_box(owner, &error),
            }
        }
        Ok(response) => return error_box(owner, &strings::import_invalid(response.message())),
        Err(error) => return error_box(owner, &call_text(&error)),
    }
    log!("{}: added from {}", name, path.display());
    with_app(|app| app.list_soon());
    let file = path.file_name().map(|file| file.to_string_lossy().to_string()).unwrap_or_default();
    let (connect, delete) = ready_dialog(owner, &name, &file);
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
fn ready_dialog(owner: HWND, name: &str, file: &str) -> (bool, bool) {
    let title = wide(names::PRODUCT);
    let instruction = wide(&strings::import_ready(name));
    let content = wide(strings::IMPORT_SAVED);
    let verification = wide(&strings::import_delete_file(file));
    let connect = wide(strings::IMPORT_CONNECT);
    let close = wide(strings::IMPORT_LATER);
    let buttons = [
        TASKDIALOG_BUTTON { nButtonID: BUTTON_CONNECT, pszButtonText: connect.as_ptr() },
        TASKDIALOG_BUTTON { nButtonID: BUTTON_CLOSE, pszButtonText: close.as_ptr() },
    ];
    let mut config: TASKDIALOGCONFIG = unsafe { zeroed() };
    config.cbSize = size_of::<TASKDIALOGCONFIG>() as u32;
    config.hwndParent = owner;
    config.hInstance = instance();
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_VERIFICATION_FLAG_CHECKED;
    config.pszWindowTitle = title.as_ptr();
    config.pszMainInstruction = instruction.as_ptr();
    config.pszContent = content.as_ptr();
    config.cButtons = buttons.len() as u32;
    config.pButtons = buttons.as_ptr();
    config.nDefaultButton = BUTTON_CONNECT;
    config.pszVerificationText = verification.as_ptr();
    let mut button = 0;
    let mut checked = 0;
    let result = unsafe { TaskDialogIndirect(&config, &mut button, ptr::null_mut(), &mut checked) };
    if result < 0 {
        // without the dialog: nothing deleted
        message_box(owner, &format!("{}\n\n{}", strings::import_ready(name), strings::IMPORT_SAVED), MB_OK);
        return (false, false);
    }
    (button == BUTTON_CONNECT, checked != 0)
}

// the import as administrator: never with the login, which stays with the user
fn admin_import(path: &Path, name: &str, replace: bool) -> String {
    let mut arguments = format!("--import {} --name {}", quote(&path.display().to_string()), quote(name));
    if replace {
        arguments += " --replace";
    }
    arguments
}

// --import <file> --name <name> [--replace], as administrator. With [--username <username> [--password
// <password>]], as the user of the VPN: the login goes in their Credential Manager, and only the import asks for an
// administrator, when they aren't allowed
pub fn import_command(path: &Path, name: &str, replace: bool, login: Option<&Login>) -> i32 {
    let fail = |message: &str| {
        error_box(ptr::null_mut(), message);
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
    match ipc::call(&Request::Import { name: name.to_string(), config: text, replace }) {
        Ok(response) if response.ok => {}
        Ok(response) if response.error_code() == ipc::ACCESS_DENIED && login.is_some() => {
            match setup::elevate(&admin_import(path, name, replace), ptr::null_mut()) {
                Ok(0) => {}
                // it said why
                Ok(code) => return code as i32,
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

pub fn remove(owner: HWND, name: &str) {
    let answer = message_box(owner, &strings::remove_confirm(name), MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if answer != IDYES {
        return;
    }
    if let Some(Some((page, interface))) = with_app(|app| app.release(name)) {
        api::logout(&page, interface, Some(QUIT_LOGOUT_TIMEOUT));
    }
    match ipc::call(&Request::Remove { name: name.to_string() }) {
        Ok(response) if response.ok => {}
        Ok(response) if response.error_code() == ipc::ACCESS_DENIED => {
            match setup::elevate(&format!("--remove {}", quote(name)), owner) {
                Ok(0) => {}
                Ok(_) => return,
                Err(error) if error == CANCELLED => return,
                Err(error) => return error_box(owner, &error),
            }
        }
        Ok(response) => return error_box(owner, response.message()),
        Err(error) => return error_box(owner, &call_text(&error)),
    }
    with_app(|app| app.removed(name));
}

// while it's off: true when it's renamed
pub fn rename(owner: HWND, name: &str, new_name: &str) -> bool {
    let request = Request::Rename { name: name.to_string(), new_name: new_name.to_string() };
    match ipc::call(&request) {
        Ok(response) if response.ok => {}
        Ok(response) if response.error_code() == ipc::ACCESS_DENIED => {
            match setup::elevate(&format!("--rename {} --to {}", quote(name), quote(new_name)), owner) {
                Ok(0) => {}
                Ok(_) => return false,
                Err(error) if error == CANCELLED => return false,
                Err(error) => {
                    error_box(owner, &error);
                    return false;
                }
            }
        }
        Ok(response) => {
            error_box(owner, &strings::rename_failed(response.message()));
            return false;
        }
        Err(error) => {
            error_box(owner, &call_text(&error));
            return false;
        }
    }
    log!("{}: renamed {}", name, new_name);
    with_app(|app| app.renamed(name, new_name));
    true
}

// --rename <name> --to <new name>, as administrator
pub fn rename_command(name: &str, new_name: &str) -> i32 {
    match ipc::call(&Request::Rename { name: name.to_string(), new_name: new_name.to_string() }) {
        Ok(response) if response.ok => 0,
        Ok(response) => {
            error_box(ptr::null_mut(), &strings::rename_failed(response.message()));
            1
        }
        Err(error) => {
            error_box(ptr::null_mut(), &call_text(&error));
            1
        }
    }
}

// --remove <name>, as administrator
pub fn remove_command(name: &str) -> i32 {
    match ipc::call(&Request::Remove { name: name.to_string() }) {
        Ok(response) if response.ok => 0,
        Ok(response) => {
            error_box(ptr::null_mut(), response.message());
            1
        }
        Err(error) => {
            error_box(ptr::null_mut(), &call_text(&error));
            1
        }
    }
}

// The tunnels go off with the app: nobody would watch their session anymore
pub fn quit(confirm: bool) {
    let active = with_app(|app| app.active_tunnels()).unwrap_or_default();
    if confirm && !active.is_empty() && message_box(ptr::null_mut(), &strings::quit_confirm(), MB_YESNO | MB_ICONQUESTION) != IDYES {
        return;
    }
    for (name, session_page) in active {
        if let Some((page, interface)) = session_page {
            api::logout(&page, interface, Some(QUIT_LOGOUT_TIMEOUT));
        }
        if let Err(error) = ipc::call(&Request::Down { name: name.clone() }) {
            log!("{}: can't disconnect: {}", name, error);
        }
    }
    super::tray::shutdown();
    unsafe { PostQuitMessage(0) };
}
