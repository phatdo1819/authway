// The keys of the device proof on Windows, see device.rs: one ECDSA P-256 key for each tunnel in the Microsoft
// Software Key Storage Provider, a key of the computer that only SYSTEM and the administrators can use, never
// exported. And the ID of the computer: its SMBIOS UUID, or MachineGuid when it has none.

use std::ptr;

use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, MS_KEY_STORAGE_PROVIDER, NCRYPT_EXPORT_POLICY_PROPERTY,
    NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemFirmwareTable, RSMB};

use crate::device::der_signature;
use crate::digest::sha256;
use crate::reg::{self, Key};
use crate::store;
use crate::win::{guid_to_string, wide};
use crate::{log, names};

pub const KIND: &str = "software";

const NTE_BAD_KEYSET: i32 = 0x80090016_u32 as i32;

// the tests run the service as the user: a key of the user
fn scope() -> NCRYPT_FLAGS {
    if cfg!(any(test, feature = "testing")) {
        NCRYPT_SILENT_FLAG
    } else {
        NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG
    }
}

fn failed(what: &str, status: i32) -> String {
    format!("{} failed: 0x{:08x}", what, status as u32)
}

struct Provider(NCRYPT_PROV_HANDLE);

impl Provider {
    fn open() -> Result<Provider, String> {
        let mut handle: NCRYPT_PROV_HANDLE = 0;
        let status = unsafe { NCryptOpenStorageProvider(&mut handle, MS_KEY_STORAGE_PROVIDER, 0) };
        if status != 0 {
            return Err(failed("NCryptOpenStorageProvider", status));
        }
        Ok(Provider(handle))
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        unsafe { NCryptFreeObject(self.0) };
    }
}

struct KeyHandle(NCRYPT_KEY_HANDLE);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

fn key_name(id: &store::Id) -> Vec<u16> {
    wide(&names::device_key(&guid_to_string(id)))
}

fn open(provider: &Provider, id: &store::Id) -> Result<Option<KeyHandle>, String> {
    let name = key_name(id);
    let mut key = KeyHandle(0);
    let status = unsafe { NCryptOpenKey(provider.0, &mut key.0, name.as_ptr(), 0, scope()) };
    match status {
        0 => Ok(Some(key)),
        NTE_BAD_KEYSET => Ok(None),
        _ => Err(failed("NCryptOpenKey", status)),
    }
}

// the key of the tunnel, made the first time
fn open_or_create(tunnel: &str, id: &store::Id) -> Result<KeyHandle, String> {
    let provider = Provider::open()?;
    if let Some(key) = open(&provider, id)? {
        return Ok(key);
    }
    let name = key_name(id);
    let mut key = KeyHandle(0);
    let status = unsafe {
        NCryptCreatePersistedKey(provider.0, &mut key.0, BCRYPT_ECDSA_P256_ALGORITHM, name.as_ptr(), 0, scope())
    };
    if status != 0 {
        return Err(failed("NCryptCreatePersistedKey", status));
    }
    // never exported, not even in an encrypted form
    let policy = 0u32.to_le_bytes();
    let status =
        unsafe { NCryptSetProperty(key.0, NCRYPT_EXPORT_POLICY_PROPERTY, policy.as_ptr(), 4, NCRYPT_SILENT_FLAG) };
    if status != 0 {
        return Err(failed("NCryptSetProperty", status));
    }
    let status = unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) };
    if status != 0 {
        return Err(failed("NCryptFinalizeKey", status));
    }
    log!("{}: new device key", tunnel);
    Ok(key)
}

// The public key of the tunnel, 04 || X || Y
pub fn public_point(tunnel: &str, id: &store::Id) -> Result<[u8; 65], String> {
    let key = open_or_create(tunnel, id)?;
    let header = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();
    let mut blob = vec![0u8; header + 64];
    let mut size = 0u32;
    let status = unsafe {
        NCryptExportKey(
            key.0,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            ptr::null(),
            blob.as_mut_ptr(),
            blob.len() as u32,
            &mut size,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return Err(failed("NCryptExportKey", status));
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    let length = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
    if size as usize != header + 64 || magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || length != 32 {
        return Err("not a P-256 public key".into());
    }
    let mut point = [4u8; 65];
    point[1..].copy_from_slice(&blob[header..header + 64]);
    Ok(point)
}

// The DER ECDSA SHA-256 signature of the data
pub fn sign(tunnel: &str, id: &store::Id, data: &[u8]) -> Result<Vec<u8>, String> {
    let key = open_or_create(tunnel, id)?;
    let hash = sha256(data);
    let mut raw = [0u8; 64];
    let mut size = 0u32;
    let status = unsafe {
        NCryptSignHash(
            key.0,
            ptr::null(),
            hash.as_ptr(),
            hash.len() as u32,
            raw.as_mut_ptr(),
            raw.len() as u32,
            &mut size,
            NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 {
        return Err(failed("NCryptSignHash", status));
    }
    if size != 64 {
        return Err("not a P-256 signature".into());
    }
    Ok(der_signature(&raw))
}

// with its tunnel, which stays enrolled: the key has the name of the GUID, which a renamed tunnel keeps
pub fn rename(_tunnel: &str, _new_name: &str, _id: &store::Id) {}

// with its tunnel: a new tunnel of the same name gets a new key, enrolled again
pub fn delete(tunnel: &str, id: &store::Id) {
    let result = Provider::open().and_then(|provider| open(&provider, id));
    match result {
        Ok(Some(mut key)) => {
            // NCryptDeleteKey frees the handle, also when it fails
            let status = unsafe { NCryptDeleteKey(key.0, NCRYPT_SILENT_FLAG) };
            key.0 = 0;
            if status != 0 {
                log!("{}: can't delete the device key: {}", tunnel, failed("NCryptDeleteKey", status));
            }
        }
        Ok(None) => {}
        Err(error) => log!("{}: can't delete the device key: {}", tunnel, error),
    }
}

pub fn computer_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

// The ID of this computer, in lower case
pub fn machine_id() -> Option<String> {
    smbios_uuid().or_else(machine_guid)
}

fn machine_guid() -> Option<String> {
    let key = Key::open(reg::HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")?;
    key.get_string("MachineGuid").map(|guid| guid.trim().to_lowercase()).filter(|guid| !guid.is_empty())
}

fn smbios_uuid() -> Option<String> {
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, ptr::null_mut(), 0) };
    if size == 0 {
        return None;
    }
    let mut data = vec![0u8; size as usize];
    let read = unsafe { GetSystemFirmwareTable(RSMB, 0, data.as_mut_ptr().cast(), size) };
    if read == 0 || read > size {
        return None;
    }
    data.truncate(read as usize);
    uuid_of_smbios(&data)
}

// The UUID of the system information structure (type 1) of a RawSMBIOSData, None when it's missing or a placeholder
pub fn uuid_of_smbios(data: &[u8]) -> Option<String> {
    // RawSMBIOSData: calling method, major, minor, DMI revision, length of the table, the table
    let major = *data.get(1)?;
    let minor = *data.get(2)?;
    let length = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?) as usize;
    let table = data.get(8..8 + length)?;
    let mut offset = 0;
    while offset + 4 <= table.len() {
        let kind = table[offset];
        let formatted = table[offset + 1] as usize;
        if formatted < 4 || offset + formatted > table.len() {
            return None;
        }
        if kind == 1 {
            let uuid = table.get(offset + 8..offset + 24)?;
            return format_uuid(uuid, (major, minor) >= (2, 6));
        }
        if kind == 127 {
            return None;
        }
        // the strings after the formatted area end with two zeros
        let mut next = offset + formatted;
        while next + 1 < table.len() && !(table[next] == 0 && table[next + 1] == 0) {
            next += 1;
        }
        offset = next + 2;
    }
    None
}

fn format_uuid(bytes: &[u8], little_endian: bool) -> Option<String> {
    // all zeros: not set, all FF: not present
    if bytes.iter().all(|&byte| byte == 0) || bytes.iter().all(|&byte| byte == 0xff) {
        return None;
    }
    let mut ordered = bytes.to_vec();
    // since SMBIOS 2.6, the first three fields are little endian
    if little_endian {
        ordered[0..4].reverse();
        ordered[4..6].reverse();
        ordered[6..8].reverse();
    }
    let text = format!(
        "{}-{}-{}-{}-{}",
        crate::digest::hex(&ordered[0..4]),
        crate::digest::hex(&ordered[4..6]),
        crate::digest::hex(&ordered[6..8]),
        crate::digest::hex(&ordered[8..10]),
        crate::digest::hex(&ordered[10..16])
    );
    // the placeholder of many boards, the same on all of them
    if text == "03000200-0400-0500-0006-000700080009" {
        return None;
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn smbios(major: u8, minor: u8, structures: &[u8]) -> Vec<u8> {
        let mut data = vec![0, major, minor, 0];
        data.extend_from_slice(&(structures.len() as u32).to_le_bytes());
        data.extend_from_slice(structures);
        data
    }

    fn system_information(uuid: [u8; 16]) -> Vec<u8> {
        // type 1, 27 bytes, handle, 4 string numbers, the UUID, then more fields and two strings
        let mut structure = vec![1, 27, 1, 0, 1, 2, 0, 0];
        structure.extend_from_slice(&uuid);
        structure.extend_from_slice(&[6, 0, 0]);
        structure.extend_from_slice(b"Maker\0Model\0\0");
        structure
    }

    #[test]
    fn smbios_uuids() {
        let uuid = [0x44, 0x45, 0x4c, 0x4c, 0x42, 0x00, 0x10, 0x35, 0x80, 0x51, 0xb4, 0xc0, 0x4f, 0x4c, 0x4d, 0x32];
        // a BIOS structure (type 0) before it, with strings
        let mut structures = vec![0, 4, 0, 0];
        structures.extend_from_slice(b"Vendor\0\0");
        structures.extend(system_information(uuid));
        structures.extend_from_slice(&[127, 4, 2, 0, 0, 0]);
        assert_eq!(
            uuid_of_smbios(&smbios(3, 4, &structures)).as_deref(),
            Some("4c4c4544-0042-3510-8051-b4c04f4c4d32")
        );
        // before 2.6, as it is
        assert_eq!(
            uuid_of_smbios(&smbios(2, 5, &structures)).as_deref(),
            Some("44454c4c-4200-1035-8051-b4c04f4c4d32")
        );
        // not set, not present, a placeholder, no structure, garbage
        assert_eq!(uuid_of_smbios(&smbios(3, 0, &system_information([0; 16]))), None);
        assert_eq!(uuid_of_smbios(&smbios(3, 0, &system_information([0xff; 16]))), None);
        let placeholder = [0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9];
        assert_eq!(uuid_of_smbios(&smbios(3, 0, &system_information(placeholder))), None);
        assert_eq!(uuid_of_smbios(&smbios(3, 0, &[127, 4, 0, 0, 0, 0])), None);
        assert_eq!(uuid_of_smbios(&[0, 3]), None);
        assert_eq!(uuid_of_smbios(&smbios(3, 0, &[1, 2, 0, 0])), None);
    }

    #[test]
    fn this_computer() {
        let id = machine_id().expect("an ID");
        assert_eq!(id.len(), 36, "{}", id);
        assert_eq!(id, id.to_lowercase());
        assert_eq!(machine_id().unwrap(), id);
    }

    // A key of the tests, signed and checked by openssl, as the firewall does
    #[test]
    fn keys_sign_for_openssl() {
        let id = crate::win::new_guid();
        let point = public_point("test", &id).unwrap();
        // the same key the second time
        assert_eq!(public_point("test", &id).unwrap(), point);
        let data = crate::device::message("C1", "S", "P", "10.103.1.2", "alice", "");
        let signature = sign("test", &id, &data).unwrap();
        assert_eq!(signature[0], 0x30);
        let folder = std::env::temp_dir().join(format!("authway-devkey-{}", guid_to_string(&id)));
        std::fs::create_dir_all(&folder).unwrap();
        let der = crate::device::spki(&point);
        std::fs::write(folder.join("key.der"), &der).unwrap();
        std::fs::write(folder.join("data"), &data).unwrap();
        std::fs::write(folder.join("signature"), &signature).unwrap();
        let verify = |file: &str| {
            Command::new("openssl")
                .args(["dgst", "-sha256", "-verify"])
                .arg(folder.join("key.der"))
                .args(["-keyform", "DER", "-signature"])
                .arg(folder.join("signature"))
                .arg(folder.join(file))
                .output()
        };
        match verify("data") {
            Ok(output) => {
                assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
                std::fs::write(folder.join("other"), b"other").unwrap();
                assert!(!verify("other").unwrap().status.success());
            }
            Err(_) => eprintln!("openssl is missing: the signature isn't checked"),
        }
        delete("test", &id);
        let provider = Provider::open().unwrap();
        assert!(open(&provider, &id).unwrap().is_none());
        // a new key after the deletion
        assert_ne!(public_point("test", &id).unwrap(), point);
        delete("test", &id);
        let _ = std::fs::remove_dir_all(folder);
    }
}
