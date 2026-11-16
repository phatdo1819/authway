// The keys of the device proof on Linux, see device.rs: one ECDSA P-256 key for each tunnel, made by openssl, the
// cryptography of the system, and kept in a file of a folder of root, readable by root only, like the configurations
// of the tunnels. The key never leaves the folder: openssl reads it there, the data to sign on its standard input.
// And the ID of the computer: its SMBIOS UUID, or /etc/machine-id when it has none.

use std::fs::{self, DirBuilder};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::commands;
use crate::device::spki;
use crate::{log, setup, store};

pub const KIND: &str = "software";

fn folder() -> PathBuf {
    setup::support_dir().join("devices")
}

fn path(tunnel: &str) -> PathBuf {
    folder().join(format!("{}.key", tunnel))
}

fn openssl() -> Result<PathBuf, String> {
    setup::tool("openssl").ok_or_else(|| "openssl isn't installed".to_string())
}

// openssl with its arguments, the input given: its output, or what it wrote as an error
fn run(arguments: &[&str], input: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(openssl()?)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("can't run openssl: {}", error))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input).map_err(|error| format!("can't write to openssl: {}", error))?;
    }
    let output = child.wait_with_output().map_err(|error| format!("openssl: {}", error))?;
    if !output.status.success() {
        return Err(format!("openssl: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(output.stdout)
}

// the key of the tunnel, made the first time: in a new file of the folder of root, then renamed
fn create(tunnel: &str) -> Result<(), String> {
    let folder = folder();
    DirBuilder::new().recursive(true).mode(0o700).create(&folder).map_err(|error| error.to_string())?;
    let _ = fs::set_permissions(&folder, fs::Permissions::from_mode(0o700));
    let temporary = folder.join(format!(".{}.new", tunnel));
    let _ = fs::remove_file(&temporary);
    let temporary_text = temporary.display().to_string();
    let made = run(&["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", &temporary_text], &[]);
    if let Err(error) = made {
        let _ = fs::remove_file(&temporary);
        return Err(format!("the device key can't be made: {}", error));
    }
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(|error| error.to_string())?;
    fs::rename(&temporary, path(tunnel)).map_err(|error| error.to_string())?;
    log!("{}: new device key", tunnel);
    Ok(())
}

// 04 || X || Y, from the DER SubjectPublicKeyInfo that openssl writes
fn point_of(tunnel: &str) -> Result<[u8; 65], String> {
    let key = path(tunnel).display().to_string();
    let der = run(&["pkey", "-in", &key, "-pubout", "-outform", "DER"], &[])?;
    let point: [u8; 65] = der.get(26..).and_then(|point| point.try_into().ok()).ok_or("not a P-256 public key")?;
    if spki(&point) != der {
        return Err("not a P-256 public key".into());
    }
    Ok(point)
}

// The public key of the tunnel, 04 || X || Y
pub fn public_point(tunnel: &str, _id: &store::Id) -> Result<[u8; 65], String> {
    if !path(tunnel).exists() {
        create(tunnel)?;
    }
    point_of(tunnel)
}

// The same, None when the tunnel has no key yet: it never logged in on a server that requires device binding
pub fn existing_point(tunnel: &str, _id: &store::Id) -> Result<Option<[u8; 65]>, String> {
    if !path(tunnel).exists() {
        return Ok(None);
    }
    point_of(tunnel).map(Some)
}

// The DER ECDSA SHA-256 signature of the data
pub fn sign(tunnel: &str, _id: &store::Id, data: &[u8]) -> Result<Vec<u8>, String> {
    if !path(tunnel).exists() {
        create(tunnel)?;
    }
    let key = path(tunnel).display().to_string();
    run(&["dgst", "-sha256", "-sign", &key], data).map_err(|error| format!("the login can't be signed: {}", error))
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
    let mut name = [0u8; 256];
    if unsafe { libc::gethostname(name.as_mut_ptr() as *mut libc::c_char, name.len()) } != 0 {
        return String::new();
    }
    let end = name.iter().position(|&byte| byte == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).to_string()
}

// The ID of this computer, in lower case: the SMBIOS UUID, which only root can read, else the ID of the system
pub fn machine_id() -> Option<String> {
    let read = |path: &str| fs::read_to_string(path).ok();
    read("/sys/class/dmi/id/product_uuid")
        .and_then(|text| commands::product_uuid(&text))
        .or_else(|| read("/etc/machine-id").and_then(|text| commands::machine_id(&text)))
}
