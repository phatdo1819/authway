// The username and password of a login page in the keyring of the user (the Secret Service of GNOME Keyring or
// KWallet) through secret-tool: an item "Authway/http://10.103.1.1:8181" with the username and the password in it,
// as JSON on its standard input and output, never on a command line. Without a keyring, the username alone goes in
// the settings of the user, and the app doesn't offer to remember the password.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::api::Page;
use crate::log;
use crate::names::{self, PRODUCT};
use crate::secret::{self, Secret};
use crate::settings;
use crate::setup;

// for the log
pub const STORE_NAME: &str = "the keyring";

#[derive(Default)]
pub struct SavedLogin {
    pub username: String,
    // None when the user didn't want it saved
    pub password: Option<Secret>,
}

#[derive(Serialize, Deserialize)]
struct Item {
    username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<Secret>,
}

// the attribute that finds the items of the app, the tests apart
fn application() -> String {
    let suffix = if cfg!(feature = "testing") { " test" } else { "" };
    format!("{}{}", PRODUCT.to_lowercase(), suffix)
}

fn secret_tool() -> Option<PathBuf> {
    setup::tool("secret-tool")
}

// secret-tool, and a session bus where the keyring answers
pub fn has_keyring() -> bool {
    secret_tool().is_some() && std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
}

fn label(page: &Page) -> String {
    format!("{}{}", names::credential_prefix(), page.authority())
}

pub fn read(page: &Page) -> SavedLogin {
    let fallback = || SavedLogin { username: settings::username(&page.authority()).unwrap_or_default(), password: None };
    let Some(tool) = secret_tool().filter(|_| has_keyring()) else { return fallback() };
    let output = Command::new(tool)
        .args(["lookup", "application", &application(), "target", &page.authority()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else { return fallback() };
    let mut data = String::from_utf8(output.stdout).unwrap_or_default();
    let saved = serde_json::from_str::<Item>(data.trim())
        .ok()
        .map(|item| SavedLogin { username: item.username, password: item.password });
    secret::wipe(&mut data);
    saved.unwrap_or_else(fallback)
}

// the username always, the password only when given
pub fn save(page: &Page, username: &str, password: Option<&str>) -> bool {
    let Some(tool) = secret_tool().filter(|_| has_keyring()) else {
        settings::set_username(&page.authority(), Some(username));
        return password.is_none();
    };
    let item = Item { username: username.to_string(), password: password.map(Secret::from) };
    let Ok(mut data) = serde_json::to_string(&item) else { return false };
    let child = Command::new(tool)
        .args(["store", &format!("--label={}", label(page)), "application", &application(), "target", &page.authority()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let saved = match child {
        Ok(mut child) => {
            let written = child.stdin.take().map(|mut stdin| stdin.write_all(data.as_bytes()));
            let output = child.wait_with_output();
            match (written, output) {
                (Some(Ok(())), Ok(output)) if output.status.success() => true,
                (_, Ok(output)) => {
                    log!("secret-tool: {}", String::from_utf8_lossy(&output.stderr).trim());
                    false
                }
                (_, Err(error)) => {
                    log!("secret-tool: {}", error);
                    false
                }
            }
        }
        Err(error) => {
            log!("secret-tool: {}", error);
            false
        }
    };
    secret::wipe(&mut data);
    if saved {
        settings::set_username(&page.authority(), None);
    }
    saved
}

fn clear(attributes: &[&str]) {
    if let Some(tool) = secret_tool().filter(|_| has_keyring()) {
        let _ = Command::new(tool).arg("clear").args(attributes).stdin(Stdio::null()).output();
    }
}

pub fn delete(page: &Page) {
    clear(&["application", &application(), "target", &page.authority()]);
    settings::set_username(&page.authority(), None);
}

// all the ones of the app, for the removal of the data of the user
pub fn delete_all() {
    clear(&["application", &application()]);
}
