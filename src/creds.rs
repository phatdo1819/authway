// The username and password of a login page in the Windows Credential Manager, which protects them with the
// Windows account of the user

use std::mem::zeroed;
use std::ptr;

use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredEnumerateW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_ENUMERATE_FLAGS,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};

use crate::api::Page;
use crate::names;
use crate::win::{from_wide_ptr, wide};

// for the log
pub const STORE_NAME: &str = "the Credential Manager";

#[derive(Default)]
pub struct SavedLogin {
    pub username: String,
    // None when the user didn't want it saved
    pub password: Option<String>,
}

// "Authway/http://10.103.1.1:8181", as the Credential Manager shows it
fn target(page: &Page) -> String {
    format!("{}{}", names::credential_prefix(), page.authority())
}

pub fn read(page: &Page) -> SavedLogin {
    let mut credential: *mut CREDENTIALW = ptr::null_mut();
    if unsafe { CredReadW(wide(&target(page)).as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
        return SavedLogin::default();
    }
    let saved = unsafe {
        let item = &*credential;
        let password = if item.CredentialBlobSize >= 2 && !item.CredentialBlob.is_null() {
            let text = std::slice::from_raw_parts(item.CredentialBlob as *const u16, item.CredentialBlobSize as usize / 2);
            Some(String::from_utf16_lossy(text))
        } else {
            None
        };
        SavedLogin { username: from_wide_ptr(item.UserName), password }
    };
    unsafe { CredFree(credential as _) };
    saved
}

// the username always, the password only when given
pub fn save(page: &Page, username: &str, password: Option<&str>) -> bool {
    let target = wide(&target(page));
    let mut username = wide(username);
    let mut blob: Vec<u16> = password.unwrap_or("").encode_utf16().collect();
    let mut credential: CREDENTIALW = unsafe { zeroed() };
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = target.as_ptr() as *mut u16;
    credential.UserName = username.as_mut_ptr();
    // this computer only: the password doesn't roam with the profile
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    if !blob.is_empty() {
        credential.CredentialBlob = blob.as_mut_ptr() as *mut u8;
        credential.CredentialBlobSize = (blob.len() * 2) as u32;
    }
    let ok = unsafe { CredWriteW(&credential, 0) } != 0;
    for item in blob.iter_mut() {
        unsafe { ptr::write_volatile(item, 0) };
    }
    ok
}

pub fn delete(page: &Page) {
    unsafe { CredDeleteW(wide(&target(page)).as_ptr(), CRED_TYPE_GENERIC, 0) };
}

// all the ones of the app, for the uninstall
pub fn delete_all() {
    let filter = wide(&format!("{}*", names::credential_prefix()));
    let mut count = 0u32;
    let mut list: *mut *mut CREDENTIALW = ptr::null_mut();
    if unsafe { CredEnumerateW(filter.as_ptr(), 0 as CRED_ENUMERATE_FLAGS, &mut count, &mut list) } == 0 {
        return;
    }
    let targets: Vec<Vec<u16>> = (0..count as usize)
        .map(|index| unsafe { wide(&from_wide_ptr((**list.add(index)).TargetName)) })
        .collect();
    unsafe { CredFree(list as _) };
    for target in targets {
        unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;

    #[test]
    fn saved_and_deleted() {
        let page = Page::parse("http://192.0.2.1:18181/").unwrap();
        delete(&page);
        assert_eq!(read(&page).username, "");
        assert!(save(&page, "alice", Some("Secret,1234")));
        let saved = read(&page);
        assert_eq!((saved.username.as_str(), saved.password.as_deref()), ("alice", Some("Secret,1234")));
        // the username only
        assert!(save(&page, "alice", None));
        assert_eq!(read(&page).password, None);
        delete_all();
        assert_eq!(read(&page).username, "");
    }
}
