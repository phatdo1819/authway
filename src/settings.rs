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

pub fn delete_user_settings() {
    let _ = reg::delete_tree(reg::HKEY_CURRENT_USER, &names::user_key());
}
