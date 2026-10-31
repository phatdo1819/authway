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
    TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOG_BUTTON, TDCBF_CANCEL_BUTTON,
    TDF_ALLOW_DIALOG_CANCELLATION, TDF_POSITION_RELATIVE_TO_WINDOW, TDF_USE_COMMAND_LINKS, TDF_USE_HICON_MAIN,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, LoadImageW, PostQuitMessage, HICON, IDYES, IMAGE_ICON, LR_DEFAULTCOLOR, MB_DEFBUTTON2, MB_ICONERROR,
    MB_ICONINFORMATION, MB_ICONQUESTION, MB_ICONWARNING, MB_OK, MB_YESNO,
};

use super::tray::{running, signal, with_app};
use super::{instance, message_box};
use crate::api;
use crate::client::import::{is_taken, load, login_page, name_for, other_name, Duplicate, Login, Ready};
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
const BUTTON_CONNECT_DELETE: i32 = 100;
const BUTTON_CONNECT: i32 = 101;
const BUTTON_LATER: i32 = 102;
const BUTTON_KEEP_BOTH: i32 = 103;
const BUTTON_REPLACE: i32 = 104;

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
    let mut name = name_for(&config, path);
    let mut replace = false;
    let known = with_app(|app| app.tunnel_names()).unwrap_or_default();
    if is_taken(&name, &known) {
        let other = other_name(&name, &known);
        match duplicate_dialog(owner, &name, &other) {
            Duplicate::KeepBoth => name = other,
            Duplicate::Replace => replace = true,
            Duplicate::Cancel => return,
        }
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
    let ready = ready_dialog(owner, &name, &file);
    if ready.deletes() {
        if let Err(error) = fs::remove_file(path) {
            log!("can't delete {}: {}", path.display(), error);
            message_box(owner, &strings::import_not_deleted(&file, &error.to_string()), MB_OK | MB_ICONWARNING);
        }
    }
    if ready.connects() {
        with_app(|app| app.connect(&name));
    }
}

// a command link shows the line after the first \n smaller, under its title
fn link(title: &str, note: &str) -> String {
    format!("{}\n{}", title, note)
}

// A dialog of command links with the icon of the app, and a Cancel button if asked: the id of the link chosen, or of
// Cancel for Esc and the close button. None when the dialog can't show
fn command_links(owner: HWND, instruction: &str, content: &str, links: &[(i32, String)], default: i32, cancel: bool) -> Option<i32> {
    let title = wide(names::PRODUCT);
    let instruction = wide(instruction);
    let content = wide(content);
    let texts: Vec<Vec<u16>> = links.iter().map(|(_, text)| wide(text)).collect();
    let buttons: Vec<TASKDIALOG_BUTTON> = links
        .iter()
        .zip(&texts)
        .map(|((id, _), text)| TASKDIALOG_BUTTON { nButtonID: *id, pszButtonText: text.as_ptr() })
        .collect();
    let mut config: TASKDIALOGCONFIG = unsafe { zeroed() };
    config.cbSize = size_of::<TASKDIALOGCONFIG>() as u32;
    config.hwndParent = owner;
    config.hInstance = instance();
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_USE_COMMAND_LINKS | TDF_POSITION_RELATIVE_TO_WINDOW;
    if cancel {
        config.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    }
    let icon = unsafe { LoadImageW(instance(), 1 as _, IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR) as HICON };
    if !icon.is_null() {
        config.dwFlags |= TDF_USE_HICON_MAIN;
        config.Anonymous1 = TASKDIALOGCONFIG_0 { hMainIcon: icon };
    }
    config.pszWindowTitle = title.as_ptr();
    config.pszMainInstruction = instruction.as_ptr();
    config.pszContent = content.as_ptr();
    config.cButtons = buttons.len() as u32;
    config.pButtons = buttons.as_ptr();
    config.nDefaultButton = default;
    let mut button = 0;
    let result = unsafe { TaskDialogIndirect(&config, &mut button, ptr::null_mut(), ptr::null_mut()) };
    if !icon.is_null() {
        unsafe { DestroyIcon(icon) };
    }
    (result >= 0).then_some(button)
}

// "There's already a VPN named Office": keep both (the default, nothing is lost), replace it, or Cancel
fn duplicate_dialog(owner: HWND, name: &str, other: &str) -> Duplicate {
    let links = [
        (BUTTON_KEEP_BOTH, link(strings::IMPORT_KEEP_BOTH, &strings::import_keep_both_note(other))),
        (BUTTON_REPLACE, link(&strings::import_replace(name), strings::IMPORT_REPLACE_NOTE)),
    ];
    let instruction = strings::import_exists(name);
    match command_links(owner, &instruction, &strings::import_exists_note(name), &links, BUTTON_KEEP_BOTH, true) {
        Some(BUTTON_KEEP_BOTH) => Duplicate::KeepBoth,
        Some(BUTTON_REPLACE) => Duplicate::Replace,
        Some(_) => Duplicate::Cancel,
        // without the dialog: nothing is lost, and the next one says the name
        None => Duplicate::KeepBoth,
    }
}

// "Office is ready", and three command links: connect and delete the file (the default), connect and keep it, not now
fn ready_dialog(owner: HWND, name: &str, file: &str) -> Ready {
    let content = format!("{}\n\n{}", strings::IMPORT_SAVED, strings::import_file_note(file));
    let links = [
        (BUTTON_CONNECT_DELETE, link(strings::IMPORT_CONNECT_DELETE, &strings::import_connect_delete_note(file))),
        (BUTTON_CONNECT, link(strings::IMPORT_CONNECT_KEEP, strings::IMPORT_CONNECT_KEEP_NOTE)),
        (BUTTON_LATER, link(strings::IMPORT_LATER, &strings::import_later_note(name))),
    ];
    match command_links(owner, &strings::import_ready(name), &content, &links, BUTTON_CONNECT_DELETE, false) {
        Some(BUTTON_CONNECT_DELETE) => Ready::ConnectAndDelete,
        Some(BUTTON_CONNECT) => Ready::Connect,
        // Esc and the close button too
        Some(_) => Ready::Later,
        None => {
            // without the dialog: not connected, nothing deleted
            message_box(owner, &format!("{}\n\n{}", strings::import_ready(name), strings::IMPORT_SAVED), MB_OK);
            Ready::Later
        }
    }
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
