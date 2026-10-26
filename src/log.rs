// A small log file, kept under 512 KB: it never contains passwords, codes or keys

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use windows_sys::Win32::System::SystemInformation::GetLocalTime;

const MAX_SIZE: u64 = 512 * 1024;

static FILE: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn init(path: PathBuf) {
    if let Some(folder) = path.parent() {
        let _ = fs::create_dir_all(folder);
    }
    *FILE.lock().unwrap_or_else(|error| error.into_inner()) = Some(path);
}

pub fn path() -> Option<PathBuf> {
    FILE.lock().unwrap_or_else(|error| error.into_inner()).clone()
}

pub fn write(args: fmt::Arguments) {
    let guard = FILE.lock().unwrap_or_else(|error| error.into_inner());
    let line = format!("{} {}\r\n", timestamp(), args);
    if cfg!(debug_assertions) || cfg!(feature = "testing") {
        eprint!("{}", line);
    }
    let Some(path) = guard.as_ref() else { return };
    if fs::metadata(path).map(|data| data.len() > MAX_SIZE).unwrap_or(false) {
        let _ = fs::rename(path, path.with_extension("old.log"));
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}

fn timestamp() -> String {
    let mut time = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut time) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
    )
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { $crate::log::write(format_args!($($arg)*)) };
}
