// The registry, through keys closed when dropped

use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
    RegSetValueExW, HKEY, KEY_READ, KEY_WRITE, REG_BINARY, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_BINARY,
    RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};

pub use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

use crate::win::{error_message, wide};

pub struct Key(HKEY);

impl Key {
    pub fn open(root: HKEY, path: &str) -> Option<Key> {
        Self::open_with(root, path, KEY_READ)
    }

    pub fn open_writable(root: HKEY, path: &str) -> Option<Key> {
        Self::open_with(root, path, KEY_READ | KEY_WRITE)
    }

    fn open_with(root: HKEY, path: &str, access: u32) -> Option<Key> {
        let mut key = ptr::null_mut();
        let result = unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, access, &mut key) };
        if result == ERROR_SUCCESS {
            Some(Key(key))
        } else {
            None
        }
    }

    pub fn create(root: HKEY, path: &str) -> Result<Key, String> {
        let mut key = ptr::null_mut();
        let result = unsafe {
            RegCreateKeyExW(
                root,
                wide(path).as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                ptr::null(),
                &mut key,
                ptr::null_mut(),
            )
        };
        if result == ERROR_SUCCESS {
            Ok(Key(key))
        } else {
            Err(format!("can't create the registry key {}: {}", path, error_message(result)))
        }
    }

    fn get(&self, name: &str, flags: u32) -> Option<Vec<u8>> {
        let name = wide(name);
        let mut size = 0u32;
        let result = unsafe {
            RegGetValueW(self.0, ptr::null(), name.as_ptr(), flags, ptr::null_mut(), ptr::null_mut(), &mut size)
        };
        if result != ERROR_SUCCESS {
            return None;
        }
        loop {
            let mut data = vec![0u8; size as usize];
            let result = unsafe {
                RegGetValueW(self.0, ptr::null(), name.as_ptr(), flags, ptr::null_mut(), data.as_mut_ptr() as _, &mut size)
            };
            match result {
                ERROR_SUCCESS => {
                    data.truncate(size as usize);
                    return Some(data);
                }
                // it grew in the meantime
                ERROR_MORE_DATA => continue,
                _ => return None,
            }
        }
    }

    pub fn get_string(&self, name: &str) -> Option<String> {
        let data = self.get(name, RRF_RT_REG_SZ)?;
        let text: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        Some(crate::win::from_wide(&text))
    }

    pub fn get_dword(&self, name: &str) -> Option<u32> {
        let data = self.get(name, RRF_RT_REG_DWORD)?;
        Some(u32::from_le_bytes(data.get(..4)?.try_into().ok()?))
    }

    pub fn get_binary(&self, name: &str) -> Option<Vec<u8>> {
        self.get(name, RRF_RT_REG_BINARY)
    }

    fn set(&self, name: &str, kind: u32, data: &[u8]) -> Result<(), String> {
        let result = unsafe { RegSetValueExW(self.0, wide(name).as_ptr(), 0, kind, data.as_ptr(), data.len() as u32) };
        if result == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(format!("can't write {} in the registry: {}", name, error_message(result)))
        }
    }

    pub fn set_string(&self, name: &str, value: &str) -> Result<(), String> {
        let data: Vec<u8> = wide(value).iter().flat_map(|c| c.to_le_bytes()).collect();
        self.set(name, REG_SZ, &data)
    }

    pub fn set_dword(&self, name: &str, value: u32) -> Result<(), String> {
        self.set(name, REG_DWORD, &value.to_le_bytes())
    }

    pub fn set_binary(&self, name: &str, value: &[u8]) -> Result<(), String> {
        self.set(name, REG_BINARY, value)
    }

    pub fn delete_value(&self, name: &str) {
        unsafe { RegDeleteValueW(self.0, wide(name).as_ptr()) };
    }

    pub fn subkeys(&self) -> Vec<String> {
        let mut names = Vec::new();
        for index in 0.. {
            let mut buffer = [0u16; 256];
            let mut length = buffer.len() as u32;
            let result = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    buffer.as_mut_ptr(),
                    &mut length,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if result == ERROR_NO_MORE_ITEMS || result != ERROR_SUCCESS {
                break;
            }
            names.push(String::from_utf16_lossy(&buffer[..length as usize]));
        }
        names
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

// deletes a key with everything in it, fine if it's missing
pub fn delete_tree(root: HKEY, path: &str) -> Result<(), String> {
    let result = unsafe { RegDeleteTreeW(root, wide(path).as_ptr()) };
    if result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(format!("can't delete the registry key {}: {}", path, error_message(result)))
    }
}
