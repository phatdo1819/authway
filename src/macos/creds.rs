// The username and password of a login page in the keychain of the user, which macOS protects with the account of
// the user: an item "Authway/http://10.103.1.1:8181", the username and the password in it

use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};
use serde::{Deserialize, Serialize};

use crate::api::Page;
use crate::names;
use crate::settings;

// for the log
pub const STORE_NAME: &str = "the keychain";
const ACCOUNT: &str = "login";

#[derive(Default)]
pub struct SavedLogin {
    pub username: String,
    // None when the user didn't want it saved
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Item {
    username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

fn service(page: &Page) -> String {
    format!("{}{}", names::credential_prefix(), page.authority())
}

fn wipe(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

pub fn read(page: &Page) -> SavedLogin {
    let Ok(mut data) = get_generic_password(&service(page), ACCOUNT) else {
        return SavedLogin::default();
    };
    let saved = serde_json::from_slice::<Item>(&data)
        .map(|item| SavedLogin { username: item.username, password: item.password })
        .unwrap_or_default();
    wipe(&mut data);
    saved
}

// the username always, the password only when given
pub fn save(page: &Page, username: &str, password: Option<&str>) -> bool {
    let item = Item { username: username.to_string(), password: password.map(str::to_string) };
    let Ok(mut data) = serde_json::to_vec(&item) else { return false };
    let service = service(page);
    let saved = set_generic_password(&service, ACCOUNT, &data).is_ok();
    wipe(&mut data);
    if saved {
        settings::add_credential(&service);
    }
    saved
}

pub fn delete(page: &Page) {
    let service = service(page);
    let _ = delete_generic_password(&service, ACCOUNT);
    settings::remove_credential(&service);
}

// all the ones of the app, for the uninstall: the settings know them
pub fn delete_all() {
    for service in settings::credentials() {
        let _ = delete_generic_password(&service, ACCOUNT);
        settings::remove_credential(&service);
    }
}
