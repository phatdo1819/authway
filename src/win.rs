// Small helpers around the Windows API

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;

// a zero-terminated UTF-16 string for the API
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

pub fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

// the text up to the first zero
pub fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// # Safety
/// `text` is null or points to a zero-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut length = 0;
    while *text.add(length) != 0 {
        length += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
}

pub fn path_from_wide(buffer: &[u16]) -> PathBuf {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    PathBuf::from(OsString::from_wide(&buffer[..end]))
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

// the text of an error code of Windows
pub fn error_message(code: u32) -> String {
    let mut buffer: *mut u16 = ptr::null_mut();
    let length = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            ptr::null(),
            code,
            0,
            &mut buffer as *mut *mut u16 as *mut u16,
            0,
            ptr::null(),
        )
    };
    if length == 0 || buffer.is_null() {
        return format!("error {}", code);
    }
    let text = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(buffer, length as usize)) };
    unsafe { LocalFree(buffer as _) };
    format!("{} (error {})", text.trim_end().trim_end_matches('.'), code)
}

pub fn last_error_message() -> String {
    error_message(last_error())
}

// A handle closed when dropped
pub struct Handle(pub HANDLE);

impl Handle {
    pub fn is_valid(&self) -> bool {
        !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

// SAFETY: a kernel handle can be used from any thread
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

pub fn exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_default()
}

pub fn exe_dir() -> PathBuf {
    exe_path().parent().map(Path::to_path_buf).unwrap_or_default()
}

pub fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut path: *mut u16 = ptr::null_mut();
    let result = unsafe { SHGetKnownFolderPath(id, 0, ptr::null_mut(), &mut path) };
    let folder = if result == 0 { Some(PathBuf::from(unsafe { from_wide_ptr(path) })) } else { None };
    unsafe { CoTaskMemFree(path as _) };
    folder
}

pub use crate::time::unix_now;

// a FILETIME count of 100 ns since 1601 as seconds since 1970, 0 for never
pub fn filetime_to_unix(time: u64) -> u64 {
    const EPOCH_DIFFERENCE: u64 = 11_644_473_600;
    (time / 10_000_000).saturating_sub(EPOCH_DIFFERENCE)
}

pub fn guid_to_string(guid: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    )
}

pub fn parse_guid(text: &str) -> Option<GUID> {
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let text = text.trim().trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = text.split('-').collect();
    if hex.len() != 32 || parts.len() != 5 || [8, 4, 4, 4, 12] != parts.iter().map(|p| p.len()).collect::<Vec<_>>()[..] {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok();
    let mut data4 = [0u8; 8];
    for (i, item) in data4.iter_mut().enumerate() {
        *item = byte(8 + i)?;
    }
    Some(GUID {
        data1: u32::from_str_radix(&hex[0..8], 16).ok()?,
        data2: u16::from_str_radix(&hex[8..12], 16).ok()?,
        data3: u16::from_str_radix(&hex[12..16], 16).ok()?,
        data4,
    })
}

pub fn new_guid() -> GUID {
    let mut guid = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
    unsafe { windows_sys::Win32::System::Com::CoCreateGuid(&mut guid) };
    guid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_round_trip() {
        let guid = new_guid();
        let text = guid_to_string(&guid);
        let back = parse_guid(&text).unwrap();
        assert_eq!(guid_to_string(&back), text);
        assert!(parse_guid("{not-a-guid}").is_none());
        assert!(parse_guid("0123456789abcdef0123456789abcdef").is_none());
    }

    #[test]
    fn filetimes() {
        assert_eq!(filetime_to_unix(0), 0);
        // 2026-01-01 00:00:00 UTC
        assert_eq!(filetime_to_unix(134_116_992_000_000_000), 1_767_225_600);
    }
}
