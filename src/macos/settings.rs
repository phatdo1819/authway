// The settings on macOS: the ones of the administrator in /Library/Preferences/<id>.plist or in a configuration
// profile (Managed Preferences), the ones of the user in a file of their own
//   sudo defaults write /Library/Preferences/io.github.phatdo1819.authway AllowUserImport -bool true

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::Page;
use crate::names::BUNDLE_ID;
use crate::setup;

// the service asks at every request: the files are read again after this
const POLICY_CACHE: Duration = Duration::from_secs(15);

// a configuration profile first, then the file of the administrator
fn policy_files() -> [PathBuf; 2] {
    [
        PathBuf::from(format!("/Library/Managed Preferences/{}.plist", BUNDLE_ID)),
        PathBuf::from(format!("/Library/Preferences/{}.plist", BUNDLE_ID)),
    ]
}

// a plist as JSON, binary or XML alike
fn read_plist(path: &PathBuf) -> Option<serde_json::Map<String, Value>> {
    if !path.exists() {
        return None;
    }
    let output = Command::new("/usr/bin/plutil").args(["-convert", "json", "-o", "-"]).arg(path).output().ok()?;
    match serde_json::from_slice::<Value>(&output.stdout).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

// true or false, 1 or 0, as defaults writes them
fn number(value: &Value) -> Option<u32> {
    match value {
        Value::Bool(flag) => Some(u32::from(*flag)),
        Value::Number(number) => number.as_u64().and_then(|number| u32::try_from(number).ok()),
        _ => None,
    }
}

static POLICY: Mutex<Option<(Instant, BTreeMap<String, u32>)>> = Mutex::new(None);

fn policy(name: &str) -> Option<u32> {
    let mut cache = POLICY.lock().unwrap_or_else(|error| error.into_inner());
    if cache.as_ref().is_none_or(|(read, _)| read.elapsed() > POLICY_CACHE) {
        let mut values = BTreeMap::new();
        for file in policy_files().iter().rev() {
            // the profile wins: it's read last
            for (key, value) in read_plist(file).unwrap_or_default() {
                if let Some(value) = number(&value) {
                    values.insert(key, value);
                }
            }
        }
        *cache = Some((Instant::now(), values));
    }
    cache.as_ref().and_then(|(_, values)| values.get(name).copied())
}

// RememberPassword = false: the app never saves the passwords
pub fn can_remember_password() -> bool {
    policy("RememberPassword") != Some(0)
}

// AllowUserImport = true: the users who aren't administrators can add and remove tunnels
pub fn users_can_manage() -> bool {
    policy("AllowUserImport") == Some(1)
}

// The settings of the user
#[derive(Serialize, Deserialize, Default)]
struct UserSettings {
    // the login page found for a tunnel without "# Login = ..."
    #[serde(default)]
    pages: BTreeMap<String, String>,
    // the items of the keychain, to remove them with the app
    #[serde(default)]
    credentials: Vec<String>,
    // the main window opens at the sign-in, unless the user turned it off
    #[serde(default, skip_serializing_if = "Option::is_none")]
    open_at_sign_in: Option<bool>,
    #[serde(default)]
    close_notice_shown: bool,
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

pub fn credentials() -> Vec<String> {
    load().credentials
}

pub fn add_credential(service: &str) {
    let mut settings = load();
    if !settings.credentials.iter().any(|known| known == service) {
        settings.credentials.push(service.to_string());
        store(&settings);
    }
}

pub fn remove_credential(service: &str) {
    let mut settings = load();
    let before = settings.credentials.len();
    settings.credentials.retain(|known| known != service);
    if settings.credentials.len() != before {
        store(&settings);
    }
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

pub fn delete_user_settings() {
    let _ = fs::remove_file(user_file());
}
