// The configurations of the tunnels on macOS: one file each in a folder of root, as /etc/wireguard, readable by
// root only. The users can't read the private keys back, only the service can.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use crate::conf;
use crate::log;
use crate::setup;

// nothing more than its name: macOS gives the interface of a tunnel a new name at every connection
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Id;

pub struct Stored {
    pub name: String,
    pub text: String,
    pub id: Id,
}

fn folder() -> PathBuf {
    setup::support_dir().join("tunnels")
}

fn path(name: &str) -> PathBuf {
    folder().join(format!("{}.conf", name))
}

pub fn list() -> Vec<Stored> {
    let Ok(entries) = fs::read_dir(folder()) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for entry in entries.flatten() {
        let file = entry.path();
        if file.extension().is_none_or(|extension| extension != "conf") {
            continue;
        }
        let Some(name) = file.file_stem().and_then(|stem| stem.to_str()).filter(|name| conf::is_valid_name(name)) else {
            continue;
        };
        match load(name) {
            Ok(stored) => result.push(stored),
            Err(error) => log!("{}: can't read the configuration: {}", name, error),
        }
    }
    result.sort_by_key(|stored| stored.name.to_lowercase());
    result
}

pub fn load(name: &str) -> Result<Stored, String> {
    let text = fs::read_to_string(path(name)).map_err(|error| error.to_string())?;
    Ok(Stored { name: name.to_string(), text, id: Id })
}

pub fn exists(name: &str) -> bool {
    path(name).exists()
}

// written whole, then renamed over the old one
pub fn save(name: &str, text: &str) -> Result<Stored, String> {
    let folder = folder();
    DirBuilder::new().recursive(true).mode(0o700).create(&folder).map_err(|error| error.to_string())?;
    // a folder made before, with other rights
    let _ = fs::set_permissions(&folder, fs::Permissions::from_mode(0o700));
    let temporary = folder.join(format!(".{}.new", name));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(text.as_bytes()).and_then(|_| file.sync_all()).map_err(|error| error.to_string())?;
    fs::rename(&temporary, path(name)).map_err(|error| error.to_string())?;
    Ok(Stored { name: name.to_string(), text: text.to_string(), id: Id })
}

pub fn delete(name: &str) -> Result<(), String> {
    match fs::remove_file(path(name)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
        _ => Ok(()),
    }
}
