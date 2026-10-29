// The keys of the device proof on macOS, see device.rs: one ECDSA P-256 key for each tunnel, made by the Security
// framework and kept in a file of a folder of root, readable by root only, like the configurations of the tunnels.
// And the ID of the computer: its IOPlatformUUID.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
};
use security_framework_sys::key::SecKeyCreateWithData;

use crate::{log, setup, store};

pub const KIND: &str = "software";

// 04 || X || Y || D
const PRIVATE_LENGTH: usize = 97;

fn folder() -> PathBuf {
    setup::support_dir().join("devices")
}

fn path(tunnel: &str) -> PathBuf {
    folder().join(format!("{}.key", tunnel))
}

fn load(tunnel: &str) -> Result<Option<SecKey>, String> {
    let data = match fs::read(path(tunnel)) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    if data.len() != PRIVATE_LENGTH {
        return Err("the device key isn't valid".into());
    }
    let string = |name| unsafe { CFString::wrap_under_get_rule(name) };
    let attributes = CFDictionary::from_CFType_pairs(&[
        (string(unsafe { kSecAttrKeyType }), string(unsafe { kSecAttrKeyTypeECSECPrimeRandom }).as_CFType()),
        (string(unsafe { kSecAttrKeyClass }), string(unsafe { kSecAttrKeyClassPrivate }).as_CFType()),
        (string(unsafe { kSecAttrKeySizeInBits }), CFNumber::from(256).as_CFType()),
    ]);
    let data = CFData::from_buffer(&data);
    let mut error = std::ptr::null_mut();
    let key =
        unsafe { SecKeyCreateWithData(data.as_concrete_TypeRef(), attributes.as_concrete_TypeRef(), &mut error) };
    if key.is_null() {
        let error = if error.is_null() {
            "unknown error".to_string()
        } else {
            unsafe { CFError::wrap_under_create_rule(error) }.to_string()
        };
        return Err(format!("the device key can't be read: {}", error));
    }
    Ok(Some(unsafe { SecKey::wrap_under_create_rule(key) }))
}

// written whole, then renamed, readable by root only
fn save(tunnel: &str, data: &[u8]) -> Result<(), String> {
    let folder = folder();
    DirBuilder::new().recursive(true).mode(0o700).create(&folder).map_err(|error| error.to_string())?;
    let _ = fs::set_permissions(&folder, fs::Permissions::from_mode(0o700));
    let temporary = folder.join(format!(".{}.new", tunnel));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(data).and_then(|_| file.sync_all()).map_err(|error| error.to_string())?;
    fs::rename(&temporary, path(tunnel)).map_err(|error| error.to_string())
}

// the key of the tunnel, made the first time
fn load_or_create(tunnel: &str) -> Result<SecKey, String> {
    if let Some(key) = load(tunnel)? {
        return Ok(key);
    }
    let mut options = GenerateKeyOptions::default();
    options.set_key_type(KeyType::ec_sec_prime_random()).set_size_in_bits(256);
    // no location: a key in memory only, kept in the file
    let key = SecKey::new(&options).map_err(|error| format!("the device key can't be made: {}", error))?;
    let data = key.external_representation().ok_or("the device key can't be saved")?;
    if data.bytes().len() != PRIVATE_LENGTH {
        return Err("not a P-256 key".into());
    }
    save(tunnel, data.bytes())?;
    log!("{}: new device key", tunnel);
    Ok(key)
}

// The public key of the tunnel, 04 || X || Y
pub fn public_point(tunnel: &str, _id: &store::Id) -> Result<[u8; 65], String> {
    let key = load_or_create(tunnel)?;
    let public = key.public_key().ok_or("no public key")?;
    let data = public.external_representation().ok_or("the public key can't be read")?;
    data.bytes().try_into().map_err(|_| "not a P-256 public key".to_string())
}

// The DER ECDSA SHA-256 signature of the data
pub fn sign(tunnel: &str, _id: &store::Id, data: &[u8]) -> Result<Vec<u8>, String> {
    let key = load_or_create(tunnel)?;
    key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
        .map_err(|error| format!("the login can't be signed: {}", error))
}

// with its tunnel, which stays enrolled
pub fn rename(tunnel: &str, new_name: &str, _id: &store::Id) {
    match fs::rename(path(tunnel), path(new_name)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            log!("{}: can't rename the device key: {}", tunnel, error)
        }
        _ => {}
    }
}

// with its tunnel: a new tunnel of the same name gets a new key, enrolled again
pub fn delete(tunnel: &str, _id: &store::Id) {
    match fs::remove_file(path(tunnel)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            log!("{}: can't delete the device key: {}", tunnel, error)
        }
        _ => {}
    }
}

pub fn computer_name() -> String {
    let output = Command::new("/usr/sbin/scutil").args(["--get", "ComputerName"]).output();
    match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        _ => String::new(),
    }
}

// The ID of this computer, in lower case
pub fn machine_id() -> Option<String> {
    let output = Command::new("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output().ok()?;
    platform_uuid(&String::from_utf8_lossy(&output.stdout))
}

// "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" in the output of ioreg
fn platform_uuid(text: &str) -> Option<String> {
    let line = text.lines().find(|line| line.contains("\"IOPlatformUUID\""))?;
    let value = line.split('=').nth(1)?.trim().trim_matches('"').to_lowercase();
    let valid = value.len() == 36 && value.chars().all(|char| char.is_ascii_hexdigit() || char == '-');
    valid.then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_uuids() {
        let text = "+-o MacBookPro18,3  <class IOPlatformExpertDevice>\n    {\n\
                    \x20     \"IOPlatformSerialNumber\" = \"C02X\"\n\
                    \x20     \"IOPlatformUUID\" = \"4C4C4544-0042-3510-8051-B4C04F4C4D32\"\n    }\n";
        assert_eq!(platform_uuid(text).as_deref(), Some("4c4c4544-0042-3510-8051-b4c04f4c4d32"));
        assert_eq!(platform_uuid("\"IOPlatformUUID\" = \"\""), None);
        assert_eq!(platform_uuid(""), None);
    }
}
