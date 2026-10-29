// The settings: the ones of the administrator in the policies of the computer or in the setup, the ones of the
// user in HKEY_CURRENT_USER

use crate::api::Page;
use crate::names;
use crate::reg::{self, Key};

fn policy(name: &str) -> Option<u32> {
    Key::open(reg::HKEY_LOCAL_MACHINE, &names::policy_key())?.get_dword(name)
}

// RememberPassword = 0: the app never saves the passwords
pub fn can_remember_password() -> bool {
    policy("RememberPassword") != Some(0)
}

// AllowUserImport = 1: the users who aren't administrators can add and remove tunnels. The policy decides when
// there's one, 0 or 1; else the choice made in the setup, next to the tunnels
pub fn users_can_manage() -> bool {
    let value = policy("AllowUserImport").or_else(|| {
        Key::open(reg::HKEY_LOCAL_MACHINE, &names::machine_key())?.get_dword("AllowUserImport")
    });
    value == Some(1)
}

// The login page found for a tunnel without "# Login = ..."
pub fn found_page(tunnel: &str) -> Option<Page> {
    let key = Key::open(reg::HKEY_CURRENT_USER, &format!(r"{}\Pages", names::user_key()))?;
    Page::parse(&key.get_string(tunnel)?)
}

pub fn set_found_page(tunnel: &str, page: Option<&Page>) {
    let path = format!(r"{}\Pages", names::user_key());
    match page {
        Some(page) => {
            if let Ok(key) = Key::create(reg::HKEY_CURRENT_USER, &path) {
                let _ = key.set_string(tunnel, &page.url());
            }
        }
        None => {
            if let Some(key) = Key::open_writable(reg::HKEY_CURRENT_USER, &path) {
                key.delete_value(tunnel);
            }
        }
    }
}

fn user_dword(name: &str) -> Option<u32> {
    Key::open(reg::HKEY_CURRENT_USER, &names::user_key())?.get_dword(name)
}

fn set_user_dword(name: &str, value: u32) {
    if let Ok(key) = Key::create(reg::HKEY_CURRENT_USER, &names::user_key()) {
        let _ = key.set_dword(name, value);
    }
}

// The main window opens at the sign-in, as when the user starts the app, unless the user turned it off
pub fn open_at_sign_in() -> bool {
    user_dword("OpenAtSignIn") != Some(0)
}

pub fn set_open_at_sign_in(open: bool) {
    set_user_dword("OpenAtSignIn", open as u32);
}

// the notice that the app keeps running when its window closes, the first time only
pub fn close_notice_shown() -> bool {
    user_dword("CloseNoticeShown") == Some(1)
}

pub fn set_close_notice_shown() {
    set_user_dword("CloseNoticeShown", 1);
}

// where the user left the main window: left, top, width and height, in pixels of the screen
pub fn window_place() -> Option<[i32; 4]> {
    let text = Key::open(reg::HKEY_CURRENT_USER, &names::user_key())?.get_string("Window")?;
    let numbers: Vec<i32> = text.split(',').filter_map(|part| part.trim().parse().ok()).collect();
    numbers.try_into().ok()
}

pub fn set_window_place(place: [i32; 4]) {
    if let Ok(key) = Key::create(reg::HKEY_CURRENT_USER, &names::user_key()) {
        let text = place.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        let _ = key.set_string("Window", &text);
    }
}

pub fn delete_user_settings() {
    let _ = reg::delete_tree(reg::HKEY_CURRENT_USER, &names::user_key());
}
