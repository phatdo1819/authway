// A small log file, kept under 512 KB: it never contains passwords, codes or keys

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

const MAX_SIZE: u64 = 512 * 1024;
// the end of a line, as the editor of the system wants it
const NEWLINE: &str = if cfg!(windows) { "\r\n" } else { "\n" };

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
    let line = format!("{} {}{}", crate::time::timestamp(), args, NEWLINE);
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

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { $crate::log::write(format_args!($($arg)*)) };
}
