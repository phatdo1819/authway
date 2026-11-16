// The settings on Linux: the ones of the administrator in /etc/authway/policy.conf, the ones of the user in a file of
// their own
//   AllowUserImport = 1      every user can add and remove VPNs, without asking for an administrator
//   RememberPassword = 0     the app never saves the passwords

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::api::Page;
use crate::commands;
use crate::names::PRODUCT;
use crate::setup;

fn policy_file() -> PathBuf {
    PathBuf::from(format!("/etc/{}/policy.conf", PRODUCT.to_lowercase()))
}

// the service asks at every request: the file is read again each time
fn policy(name: &str) -> Option<bool> {
    commands::policy(&fs::read_to_string(policy_file()).ok()?, name)
}

// RememberPassword = 0: the app never saves the passwords. Nor without a keyring to save them in.
pub fn can_remember_password() -> bool {
    policy("RememberPassword") != Some(false) && crate::creds::has_keyring()
}

// AllowUserImport = 1: the users who aren't administrators can add and remove tunnels. The packages write it.
pub fn users_can_manage() -> bool {
    policy("AllowUserImport") == Some(true)
}

// The settings of the user
#[derive(Serialize, Deserialize, Default)]
struct UserSettings {
    // the login page found for a tunnel without "# Login = ..."
    #[serde(default)]
    pages: BTreeMap<String, String>,
    // the usernames, by login page, without a keyring for them
    #[serde(default)]
    usernames: BTreeMap<String, String>,
    // the main window opens at the sign-in, unless the user turned it off
    #[serde(default, skip_serializing_if = "Option::is_none")]
    open_at_sign_in: Option<bool>,
    #[serde(default)]
    close_notice_shown: bool,
    // the VPN that was on when the session ended, see reconnect()
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconnect: Option<String>,
}

fn user_file() -> PathBuf {
    setup::user_data_dir().join("settings.json")
}

fn load() -> UserSettings {
    fs::read(user_file()).ok().and_then(|data| serde_json::from_slice(&data).ok()).unwrap_or_default()
}

fn store(settings: &UserSettings) {
    let file = user_file();
    if let Some(folder) = file.parent() {
        let _ = fs::create_dir_all(folder);
    }
    if let Ok(data) = serde_json::to_vec_pretty(settings) {
        let _ = fs::write(file, data);
    }
}

pub fn found_page(tunnel: &str) -> Option<Page> {
    Page::parse(load().pages.get(tunnel)?)
}

pub fn set_found_page(tunnel: &str, page: Option<&Page>) {
    let mut settings = load();
    match page {
        Some(page) => {
            settings.pages.insert(tunnel.to_string(), page.url());
        }
        None => {
            if settings.pages.remove(tunnel).is_none() {
                return;
            }
        }
    }
    store(&settings);
}

// the username for a login page, on a computer without a keyring
pub fn username(page: &str) -> Option<String> {
    load().usernames.get(page).cloned()
}

pub fn set_username(page: &str, username: Option<&str>) {
    let mut settings = load();
    match username {
        Some(username) => {
            settings.usernames.insert(page.to_string(), username.to_string());
        }
        None => {
            if settings.usernames.remove(page).is_none() {
                return;
            }
        }
    }
    store(&settings);
}

// The main window opens at the sign-in, as when the user starts the app, unless the user turned it off
pub fn open_at_sign_in() -> bool {
    load().open_at_sign_in != Some(false)
}

pub fn set_open_at_sign_in(open: bool) {
    let mut settings = load();
    settings.open_at_sign_in = Some(open);
    store(&settings);
}

// the notice that the app keeps running when its window closes, the first time only
pub fn close_notice_shown() -> bool {
    load().close_notice_shown
}

pub fn set_close_notice_shown() {
    let mut settings = load();
    settings.close_notice_shown = true;
    store(&settings);
}

// The VPN that was on when the session of the user ended, with a restart or a logout: the app turns it on again at
// its next start. The user turning it off, or quitting the app, forgets it
pub fn reconnect() -> Option<String> {
    load().reconnect.filter(|name| !name.is_empty())
}

pub fn set_reconnect(tunnel: Option<&str>) {
    let mut settings = load();
    if settings.reconnect.as_deref() == tunnel {
        return;
    }
    settings.reconnect = tunnel.map(str::to_string);
    store(&settings);
}

pub fn delete_user_settings() {
    let _ = fs::remove_file(user_file());
}
