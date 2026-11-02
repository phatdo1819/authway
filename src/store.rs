// The configurations of the tunnels, in the registry of the computer, encrypted by DPAPI for the account of the
// service, SYSTEM: the users can't read the private keys back, only the service can

use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::System::Registry::HKEY;

use crate::conf;
use crate::log;
use crate::names;
use crate::reg::{self, Key};
use crate::win::{last_error_message, new_guid, parse_guid, guid_to_string};

const ENTROPY: &[u8] = b"tunnel configuration";
// the keys this computer made for the tunnel, see conf::OwnKeys, encrypted the same way
const KEYS: &str = "Keys";

// of the network adapter of a tunnel: the same at every connection, for Windows to know the network again
pub type Id = GUID;

pub struct Stored {
    pub name: String,
    pub text: String,
    pub id: Id,
}

// the tests run the service as the user
fn root() -> HKEY {
    if cfg!(feature = "testing") {
        reg::HKEY_CURRENT_USER
    } else {
        reg::HKEY_LOCAL_MACHINE
    }
}

fn path(name: &str) -> String {
    format!(r"{}\{}", names::tunnels_key(), name)
}

pub fn list() -> Vec<Stored> {
    let Some(key) = Key::open(root(), &names::tunnels_key()) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for name in key.subkeys() {
        if !conf::is_valid_name(&name) {
            continue;
        }
        match load(&name) {
            Ok(stored) => result.push(stored),
            Err(error) => log!("{}: can't read the configuration: {}", name, error),
        }
    }
    result.sort_by_key(|stored| stored.name.to_lowercase());
    result
}

pub fn load(name: &str) -> Result<Stored, String> {
    let key = Key::open(root(), &path(name)).ok_or("not found")?;
    let blob = key.get_binary("Config").ok_or("no configuration")?;
    let text = String::from_utf8(unprotect(&blob)?).map_err(|_| "not UTF-8")?;
    let id = key.get_string("Guid").as_deref().and_then(parse_guid).ok_or("no GUID")?;
    Ok(Stored { name: name.to_string(), text, id })
}

pub fn exists(name: &str) -> bool {
    Key::open(root(), &path(name)).is_some()
}

// a tunnel replaced keeps its GUID
pub fn save(name: &str, text: &str) -> Result<Stored, String> {
    let blob = protect(text.as_bytes())?;
    let key = Key::create(root(), &path(name))?;
    let guid = match key.get_string("Guid").as_deref().and_then(parse_guid) {
        Some(guid) => guid,
        None => {
            let guid = new_guid();
            key.set_string("Guid", &guid_to_string(&guid))?;
            guid
        }
    };
    key.set_binary("Config", &blob)?;
    // another configuration file: the keys made for the old one don't belong to it
    key.delete_value(KEYS);
    Ok(Stored { name: name.to_string(), text: text.to_string(), id: guid })
}

pub fn load_keys(name: &str) -> conf::OwnKeys {
    let Some(blob) = Key::open(root(), &path(name)).and_then(|key| key.get_binary(KEYS)) else {
        return conf::OwnKeys::default();
    };
    match unprotect(&blob).map(|data| String::from_utf8(data).unwrap_or_default()) {
        Ok(text) => conf::OwnKeys::from_text(&text),
        Err(error) => {
            log!("{}: can't read the keys of this computer: {}", name, error);
            conf::OwnKeys::default()
        }
    }
}

pub fn save_keys(name: &str, keys: &conf::OwnKeys) -> Result<(), String> {
    let key = Key::open_writable(root(), &path(name)).ok_or("not found")?;
    if keys.is_empty() {
        key.delete_value(KEYS);
        return Ok(());
    }
    key.set_binary(KEYS, &protect(keys.to_text().as_bytes())?)
}

pub fn delete(name: &str) -> Result<(), String> {
    reg::delete_tree(root(), &path(name))
}

// with its GUID, so the device key and the network that Windows knows stay. The registry refuses a new case
// alone: through a name that the list skips
pub fn rename(name: &str, new_name: &str) -> Result<(), String> {
    if name.eq_ignore_ascii_case(new_name) {
        let between = format!(".{}", new_name);
        reg::rename(root(), &path(name), &between)?;
        return reg::rename(root(), &path(&between), new_name);
    }
    reg::rename(root(), &path(name), new_name)
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
}

fn take(output: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let data = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        // the decrypted configuration holds the private key
        ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData as _);
    }
    data
}

fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
    let ok = unsafe {
        CryptProtectData(
            &blob(data),
            crate::win::wide(names::PRODUCT).as_ptr(),
            &blob(ENTROPY),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(format!("can't encrypt: {}", last_error_message()));
    }
    Ok(take(output))
}

fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
    let ok = unsafe {
        CryptUnprotectData(
            &blob(data),
            ptr::null_mut(),
            &blob(ENTROPY),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(format!("can't decrypt: {}", last_error_message()));
    }
    Ok(take(output))
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;

    #[test]
    fn saved_encrypted() {
        let name = "store test";
        let first = save(name, "secret text").unwrap();
        let blob = Key::open(root(), &path(name)).unwrap().get_binary("Config").unwrap();
        assert!(!blob.windows(6).any(|part| part == b"secret"));
        let read = load(name).unwrap();
        assert_eq!(read.text, "secret text");
        // the keys this computer made, encrypted too, then gone with a new configuration
        let keys = conf::OwnKeys { own: Some([3; 32]), pending: None };
        save_keys(name, &keys).unwrap();
        assert_eq!(load_keys(name), keys);
        let blob = Key::open(root(), &path(name)).unwrap().get_binary(KEYS).unwrap();
        assert!(!blob.windows(3).any(|part| part == b"own"));
        save(name, "secret text").unwrap();
        assert_eq!(load_keys(name), conf::OwnKeys::default());
        save_keys(name, &keys).unwrap();
        save_keys(name, &conf::OwnKeys::default()).unwrap();
        assert!(load_keys(name).is_empty());
        // replaced, with the same GUID
        let second = save(name, "other").unwrap();
        assert_eq!(guid_to_string(&first.id), guid_to_string(&second.id));
        assert!(list().iter().any(|stored| stored.name == name));
        save_keys(name, &keys).unwrap();
        // renamed, with the same GUID; only the case too
        rename(name, "store test 2").unwrap();
        assert!(!exists(name));
        assert_eq!(guid_to_string(&load("store test 2").unwrap().id), guid_to_string(&first.id));
        // the keys follow
        assert_eq!(load_keys("store test 2"), keys);
        rename("store test 2", name).unwrap();
        rename(name, "Store Test").unwrap();
        assert!(list().iter().any(|stored| stored.name == "Store Test"));
        rename("Store Test", name).unwrap();
        delete(name).unwrap();
        assert!(!exists(name));
        assert!(load(name).is_err());
    }
}
