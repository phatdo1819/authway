// How the app talks to the service: one JSON request and one JSON answer per connection, each on one line. On
// Windows through the named pipe of the service, on macOS through its socket.

#[cfg(windows)]
use std::mem::{size_of, zeroed};
#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PIPE_BUSY, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_GENERIC_READ, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
#[cfg(windows)]
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
};

#[cfg(windows)]
use crate::names;
#[cfg(windows)]
use crate::win::{error_message, last_error, wide, Handle};

#[cfg(target_os = "macos")]
pub use unix::{call, peer_uid, read_from, write_to};

pub const MAX_MESSAGE: usize = 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    List,
    Up { name: String },
    Down { name: String },
    Import { name: String, config: String, #[serde(default)] replace: bool },
    Remove { name: String },
    // while it's off: its device key and its login stay
    Rename { name: String, new_name: String },
    // the user logged in on the login page, or the session ended: the routes and the DNS servers that wait for the
    // login go on, or off again
    LoggedIn { name: String, logged_in: bool },
    // the device proof of a login on the page at `host`, see device.rs
    Sign {
        name: String,
        host: std::net::Ipv4Addr,
        challenge: String,
        username: String,
        #[serde(default)]
        machine_id: bool,
    },
}

// the errors of the service
pub const ACCESS_DENIED: &str = "access_denied";
pub const NOT_FOUND: &str = "not_found";
pub const EXISTS: &str = "exists";
pub const INVALID: &str = "invalid";
pub const FAILED: &str = "failed";

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    // for the user, in the language of the app
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnels: Vec<TunnelInfo>,
    // the answer to Sign
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<crate::device::Proof>,
    // whether the user who asked can add and remove tunnels without asking to be administrator
    #[serde(default)]
    pub can_manage: bool,
}

impl Response {
    pub fn success() -> Response {
        Response { ok: true, ..Response::default() }
    }

    pub fn failure(error: &str, message: impl Into<String>) -> Response {
        Response { ok: false, error: Some(error.to_string()), message: Some(message.into()), ..Response::default() }
    }

    pub fn error_code(&self) -> &str {
        self.error.as_deref().unwrap_or("")
    }

    pub fn message(&self) -> &str {
        self.message.as_deref().unwrap_or("")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct TunnelInfo {
    pub name: String,
    pub up: bool,
    // "# Login = ..." of the configuration
    #[serde(default)]
    pub login: Option<String>,
    // "# Name = ..." of the server
    #[serde(default)]
    pub server: Option<String>,
    // of the first server: the one in use while it's on, a fallback maybe
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub routes: Vec<String>,
    // with a login page: the routes to the internet, which wait for the login; its DNS servers wait too
    #[serde(default)]
    pub after_login: Vec<String>,
    // while it's on: the app said the user logged in, the routes and the DNS servers of after the login are on
    #[serde(default)]
    pub logged_in: bool,
    // the index of the network adapter of the tunnel while it's on, 0 else: the requests to the login page go out
    // only through it
    #[serde(default)]
    pub interface: u32,
    // seconds since 1970, 0 for never
    #[serde(default)]
    pub since: u64,
    #[serde(default)]
    pub handshake: u64,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    // the rest of the configuration, for the window of details: never a private or preshared key
    #[serde(default)]
    pub public_key: String,
    // "# Name = ..." of the interface: the name of this device on the server
    #[serde(default)]
    pub device: Option<String>,
    // 0 for any
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub dns_search: Vec<String>,
    // the one of the configuration, 0 for automatic
    #[serde(default)]
    pub mtu: u32,
    // the one of the adapter, while it's on
    #[serde(default)]
    pub mtu_in_use: u32,
    #[serde(default)]
    pub peers: Vec<PeerInfo>,
}

// A server of a tunnel, a [Peer] of its configuration
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct PeerInfo {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: bool,
    // as in the configuration: a name or an address, with the port
    #[serde(default)]
    pub endpoint: String,
    // "# Fallback = ...", the same way
    #[serde(default)]
    pub fallbacks: Vec<String>,
    // while it's on: the endpoint or the fallback that the tunnel sends to, and its address
    #[serde(default)]
    pub in_use: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    // seconds, 0 for off
    #[serde(default)]
    pub keepalive: u16,
    #[serde(default)]
    pub handshake: u64,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
}

#[cfg(windows)]
pub fn write_message<T: Serialize>(pipe: HANDLE, message: &T) -> Result<(), String> {
    let mut data = serde_json::to_vec(message).map_err(|error| error.to_string())?;
    data.push(b'\n');
    let mut written = 0usize;
    while written < data.len() {
        let mut count = 0u32;
        let chunk = &data[written..];
        let ok = unsafe { WriteFile(pipe, chunk.as_ptr(), chunk.len() as u32, &mut count, ptr::null_mut()) };
        if ok == 0 {
            return Err(format!("can't write to the service: {}", error_message(last_error())));
        }
        written += count as usize;
    }
    Ok(())
}

#[cfg(windows)]
pub fn read_message<T: DeserializeOwned>(pipe: HANDLE) -> Result<T, String> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let mut count = 0u32;
        let ok = unsafe { ReadFile(pipe, buffer.as_mut_ptr(), buffer.len() as u32, &mut count, ptr::null_mut()) };
        if ok == 0 {
            let code = last_error();
            if code == ERROR_BROKEN_PIPE {
                break;
            }
            if code != ERROR_MORE_DATA {
                return Err(format!("can't read from the pipe: {}", error_message(code)));
            }
        }
        data.extend_from_slice(&buffer[..count as usize]);
        if data.contains(&b'\n') {
            break;
        }
        if data.len() > MAX_MESSAGE {
            return Err("the message is too long".to_string());
        }
        if ok != 0 && count == 0 {
            break;
        }
    }
    let end = data.iter().position(|&byte| byte == b'\n').unwrap_or(data.len());
    serde_json::from_slice(&data[..end]).map_err(|error| format!("not a message: {}", error))
}

// the process of the service, to know that the pipe is its own and not one of a program that took its name
#[cfg(windows)]
pub fn service_process_id() -> Option<u32> {
    unsafe {
        let manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return None;
        }
        let service = OpenServiceW(manager, wide(names::SERVICE_NAME).as_ptr(), SERVICE_QUERY_STATUS);
        let mut result = None;
        if !service.is_null() {
            let mut status: SERVICE_STATUS_PROCESS = zeroed();
            let mut needed = 0u32;
            let ok = QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                &mut status as *mut _ as *mut u8,
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            );
            if ok != 0 && status.dwCurrentState == SERVICE_RUNNING {
                result = Some(status.dwProcessId);
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(manager);
        result
    }
}

#[derive(Debug)]
pub enum CallError {
    // the service isn't installed or isn't running
    Unavailable,
    Failed(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CallError::Unavailable => f.write_str("the service isn't running"),
            CallError::Failed(message) => f.write_str(message),
        }
    }
}

#[cfg(windows)]
fn connect() -> Result<Handle, CallError> {
    let name = wide(&names::pipe());
    for _ in 0..10 {
        // GENERIC_WRITE would ask for FILE_CREATE_PIPE_INSTANCE too, which the users don't have; the service can
        // only know who we are, not act as us
        let pipe = Handle(unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ | FILE_WRITE_DATA,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        });
        if pipe.is_valid() {
            return Ok(pipe);
        }
        match last_error() {
            ERROR_PIPE_BUSY => {
                unsafe { WaitNamedPipeW(name.as_ptr(), 2000) };
            }
            ERROR_FILE_NOT_FOUND => return Err(CallError::Unavailable),
            code => return Err(CallError::Failed(format!("can't reach the service: {}", error_message(code)))),
        }
    }
    Err(CallError::Failed("the service is busy".to_string()))
}

#[cfg(windows)]
fn check_server(pipe: &Handle) -> Result<(), CallError> {
    if cfg!(feature = "testing") {
        return Ok(());
    }
    let mut server = 0u32;
    if unsafe { GetNamedPipeServerProcessId(pipe.0, &mut server) } == 0 {
        return Err(CallError::Failed(format!("can't check the service: {}", error_message(last_error()))));
    }
    match service_process_id() {
        Some(service) if service == server => Ok(()),
        Some(_) => Err(CallError::Failed("another program took the name of the pipe of the service".to_string())),
        None => Err(CallError::Unavailable),
    }
}

#[cfg(windows)]
pub fn call(request: &Request) -> Result<Response, CallError> {
    let pipe = connect()?;
    check_server(&pipe)?;
    write_message(pipe.0, request).map_err(CallError::Failed)?;
    read_message(pipe.0).map_err(CallError::Failed)
}

// The socket of the service: only root can create it where it is, and the app checks that root answers
#[cfg(target_os = "macos")]
mod unix {
    use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use serde::de::DeserializeOwned;
    use serde::Serialize;

    use super::{CallError, Request, Response, MAX_MESSAGE};
    use crate::names;

    // a tunnel turns on in a few seconds, the lookups of its servers included
    const TIMEOUT: Duration = Duration::from_secs(60);

    pub fn write_to<T: Serialize>(stream: &mut impl Write, message: &T) -> Result<(), String> {
        let mut data = serde_json::to_vec(message).map_err(|error| error.to_string())?;
        data.push(b'\n');
        stream
            .write_all(&data)
            .and_then(|_| stream.flush())
            .map_err(|error| format!("can't write to the service: {}", error))
    }

    pub fn read_from<T: DeserializeOwned>(stream: &mut impl Read) -> Result<T, String> {
        let mut data = Vec::new();
        let mut reader = BufReader::new(Read::take(stream, MAX_MESSAGE as u64 + 1));
        reader.read_until(b'\n', &mut data).map_err(|error| format!("can't read from the socket: {}", error))?;
        if data.len() > MAX_MESSAGE {
            return Err("the message is too long".to_string());
        }
        let end = data.iter().position(|&byte| byte == b'\n').unwrap_or(data.len());
        serde_json::from_slice(&data[..end]).map_err(|error| format!("not a message: {}", error))
    }

    // the user at the other end of a connection
    pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
        let (mut uid, mut gid) = (0, 0);
        (unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(uid)
    }

    fn check_server(stream: &UnixStream) -> Result<(), CallError> {
        if cfg!(feature = "testing") {
            return Ok(());
        }
        let socket = std::fs::symlink_metadata(names::socket_path());
        let owned = socket.is_ok_and(|socket| socket.file_type().is_socket() && socket.uid() == 0);
        if !owned || peer_uid(stream) != Some(0) {
            return Err(CallError::Failed("another program took the name of the socket of the service".to_string()));
        }
        Ok(())
    }

    pub fn call(request: &Request) -> Result<Response, CallError> {
        let mut stream = match UnixStream::connect(names::socket_path()) {
            Ok(stream) => stream,
            Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                return Err(CallError::Unavailable)
            }
            Err(error) => return Err(CallError::Failed(format!("can't reach the service: {}", error))),
        };
        check_server(&stream)?;
        let _ = stream.set_read_timeout(Some(TIMEOUT));
        let _ = stream.set_write_timeout(Some(TIMEOUT));
        write_to(&mut stream, request).map_err(CallError::Failed)?;
        read_from(&mut stream).map_err(CallError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages() {
        let request = Request::Import { name: "Office".into(), config: "[Interface]".into(), replace: false };
        let text = serde_json::to_string(&request).unwrap();
        assert_eq!(text, r#"{"op":"import","name":"Office","config":"[Interface]","replace":false}"#);
        let back: Request = serde_json::from_str(r#"{"op":"import","name":"Office","config":"x"}"#).unwrap();
        assert!(matches!(back, Request::Import { replace: false, .. }));
        assert_eq!(serde_json::to_string(&Request::List).unwrap(), r#"{"op":"list"}"#);
        let response = Response::failure(ACCESS_DENIED, "only administrators");
        let back: Response = serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
        assert_eq!((back.ok, back.error_code(), back.message()), (false, ACCESS_DENIED, "only administrators"));
        assert!(serde_json::from_str::<Request>(r#"{"op":"format_disk"}"#).is_err());
    }
}
