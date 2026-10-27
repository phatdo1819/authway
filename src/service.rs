// The Windows service, as SYSTEM: it keeps the configurations of the tunnels and turns them on and off for the
// app of the users, through its named pipe. A tunnel is turned off when the user who turned it on signs out.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
#[cfg(not(feature = "testing"))]
use std::net::SocketAddr;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

#[cfg(not(feature = "testing"))]
use windows_sys::core::GUID;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, NO_ERROR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, RevertToSelf, WinBuiltinAdministratorsSid, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientSessionId, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::RemoteDesktop::WTSSESSION_NOTIFICATION;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW, SERVICE_ACCEPT_SESSIONCHANGE,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SESSIONCHANGE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows_sys::Win32::UI::WindowsAndMessaging::WTS_SESSION_LOGOFF;

#[cfg(not(feature = "testing"))]
use crate::conf::{self, Config};
use crate::ipc::{self, Request, Response};
use crate::log;
#[cfg(not(feature = "testing"))]
use crate::manager::{PeerStats, Tunnel};
use crate::manager::{self, Client, Engine, Manager};
use crate::names;
use crate::settings;
use crate::win::{error_message, last_error, last_error_message, wide, Handle};

// SYSTEM and the administrators; the users who are signed in on the computer can read and write, but not create
// instances of the pipe (FILE_CREATE_PIPE_INSTANCE): no other program can answer in place of the service
#[cfg(not(feature = "testing"))]
const PIPE_SECURITY: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";
#[cfg(feature = "testing")]
const PIPE_SECURITY: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";

#[cfg(not(feature = "testing"))]
struct DriverTunnel {
    adapter: crate::wg::Adapter,
    mtu: u32,
    interface: u32,
}

#[cfg(not(feature = "testing"))]
impl Tunnel for DriverTunnel {
    fn peers(&self) -> Vec<PeerStats> {
        self.adapter.peers().unwrap_or_default()
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn interface(&self) -> u32 {
        self.interface
    }

    fn set_endpoint(&mut self, public_key: &conf::Key, address: SocketAddr) -> Result<(), String> {
        self.adapter.set_endpoint(public_key, &address)
    }
}

// WireGuardNT, loaded at the first tunnel turned on
#[cfg(not(feature = "testing"))]
#[derive(Default)]
struct DriverEngine {
    wireguard: Option<Arc<crate::wg::WireGuard>>,
}

#[cfg(not(feature = "testing"))]
impl Engine for DriverEngine {
    fn start(
        &mut self,
        name: &str,
        guid: &GUID,
        config: &Config,
        endpoints: &[Option<SocketAddr>],
    ) -> Result<Box<dyn Tunnel>, String> {
        use crate::{net, wg};
        if self.wireguard.is_none() {
            self.wireguard = Some(wg::WireGuard::load()?);
        }
        let wireguard = self.wireguard.as_ref().expect("loaded");
        let adapter = wg::Adapter::create(wireguard, name, names::PRODUCT, guid)?;
        let mtu = match config.mtu {
            Some(mtu) => mtu as u32,
            None => endpoints.iter().flatten().next().map(net::auto_mtu).unwrap_or(net::DEFAULT_MTU),
        };
        net::configure(adapter.luid(), config, mtu)?;
        let interface = net::interface_index(adapter.luid())?;
        adapter.set_config(config, endpoints)?;
        adapter.set_up(true)?;
        let servers: Vec<String> = endpoints.iter().flatten().map(ToString::to_string).collect();
        log!(
            "{}: to {}, MTU {}, driver {}",
            name,
            servers.join(", "),
            mtu,
            wireguard.driver_version().unwrap_or_else(|| "?".to_string())
        );
        Ok(Box::new(DriverTunnel { adapter, mtu, interface }))
    }
}

#[cfg(not(feature = "testing"))]
fn engine() -> Box<dyn Engine> {
    Box::new(DriverEngine::default())
}

#[cfg(feature = "testing")]
fn engine() -> Box<dyn Engine> {
    Box::new(manager::fake::FakeEngine)
}

fn is_administrator(pipe: HANDLE) -> bool {
    unsafe {
        // the client allows only its identification: enough to read its groups
        if ImpersonateNamedPipeClient(pipe) == 0 {
            return false;
        }
        let mut token: HANDLE = ptr::null_mut();
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
        RevertToSelf();
        if opened == 0 {
            return false;
        }
        let token = Handle(token);
        let mut sid = [0u8; 68];
        let mut size = sid.len() as u32;
        if CreateWellKnownSid(WinBuiltinAdministratorsSid, ptr::null_mut(), sid.as_mut_ptr() as _, &mut size) == 0 {
            return false;
        }
        let mut member = 0;
        // without elevation the token of an administrator has the group only to deny
        CheckTokenMembership(token.0, sid.as_mut_ptr() as _, &mut member) != 0 && member != 0
    }
}

fn client_of(pipe: HANDLE) -> Client {
    let mut session = u32::MAX;
    unsafe { GetNamedPipeClientSessionId(pipe, &mut session) };
    let can_manage = if cfg!(feature = "testing") {
        std::env::var("AUTHWAY_TEST_DENY").is_err()
    } else {
        is_administrator(pipe) || settings::users_can_manage()
    };
    Client { session, can_manage }
}

struct Server {
    manager: Mutex<Manager>,
    stopping: AtomicBool,
}

impl Server {
    fn new() -> Arc<Server> {
        Arc::new(Server { manager: Mutex::new(Manager::load(engine())), stopping: AtomicBool::new(false) })
    }

    fn serve_client(&self, pipe: Handle) {
        let response = match ipc::read_message::<Request>(pipe.0) {
            Ok(request) => {
                let client = client_of(pipe.0);
                let mut manager = self.manager.lock().unwrap_or_else(|error| error.into_inner());
                manager.handle(request, &client)
            }
            Err(error) => Response::failure(ipc::INVALID, error),
        };
        if let Err(error) = ipc::write_message(pipe.0, &response) {
            log!("{}", error);
        }
        unsafe {
            FlushFileBuffers(pipe.0);
            DisconnectNamedPipe(pipe.0);
        }
    }

    // a connection per request, each on its own thread
    fn listen(self: Arc<Self>) {
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(PIPE_SECURITY).as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            log!("can't make the security of the pipe: {}", last_error_message());
            return;
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let name = wide(&names::pipe());
        let mut first = true;
        while !self.stopping.load(Ordering::SeqCst) {
            let mode = if first { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX };
            let pipe = Handle(unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    mode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    64 * 1024,
                    64 * 1024,
                    0,
                    &attributes,
                )
            });
            if !pipe.is_valid() {
                log!("can't create the pipe: {}", last_error_message());
                if first {
                    // another program has it
                    return;
                }
                thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
            first = false;
            let connected = unsafe { ConnectNamedPipe(pipe.0, ptr::null_mut()) } != 0 || last_error() == ERROR_PIPE_CONNECTED;
            if self.stopping.load(Ordering::SeqCst) {
                break;
            }
            if !connected {
                continue;
            }
            let server = self.clone();
            thread::spawn(move || server.serve_client(pipe));
        }
        unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor as _) };
    }

    fn watch(&self) {
        manager::watch_loop(&self.manager, &self.stopping, |_, _| {});
    }

    // the pipe waits for a connection: one wakes it up
    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _wake = Handle(unsafe {
            CreateFileW(
                wide(&names::pipe()).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        });
        self.manager.lock().unwrap_or_else(|error| error.into_inner()).stop();
    }
}

enum Control {
    Stop,
    SignedOut(u32),
}

static CONTROL: OnceLock<Mutex<Sender<Control>>> = OnceLock::new();

unsafe extern "system" fn control_handler(control: u32, event: u32, data: *mut c_void, _context: *mut c_void) -> u32 {
    let send = |message| {
        if let Some(sender) = CONTROL.get() {
            let _ = sender.lock().unwrap_or_else(|error| error.into_inner()).send(message);
        }
    };
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            send(Control::Stop);
            NO_ERROR
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            if event == WTS_SESSION_LOGOFF && !data.is_null() {
                let notification = &*(data as *const WTSSESSION_NOTIFICATION);
                send(Control::SignedOut(notification.dwSessionId));
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn set_status(handle: SERVICE_STATUS_HANDLE, state: SERVICE_STATUS_CURRENT_STATE, accepted: u32, exit_code: u32) {
    let mut status: SERVICE_STATUS = unsafe { zeroed() };
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = accepted;
    status.dwWin32ExitCode = exit_code;
    status.dwWaitHint = if state == SERVICE_RUNNING || state == SERVICE_STOPPED { 0 } else { 10_000 };
    unsafe { SetServiceStatus(handle, &status) };
}

pub fn log_path() -> std::path::PathBuf {
    crate::win::exe_dir().join("log").join("service.log")
}

unsafe extern "system" fn service_main(_count: u32, _arguments: *mut PWSTR) {
    log::init(log_path());
    let (sender, receiver) = mpsc::channel();
    let _ = CONTROL.set(Mutex::new(sender));
    let handle = RegisterServiceCtrlHandlerExW(wide(names::SERVICE_NAME).as_ptr(), Some(control_handler), ptr::null());
    if handle.is_null() {
        log!("can't register the service: {}", last_error_message());
        return;
    }
    set_status(handle, SERVICE_START_PENDING, 0, NO_ERROR);
    log!("{} {}: service started", names::PRODUCT, names::VERSION);
    let server = Server::new();
    let listener = {
        let server = server.clone();
        thread::spawn(move || server.listen())
    };
    let watcher = {
        let server = server.clone();
        thread::spawn(move || server.watch())
    };
    set_status(
        handle,
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE,
        NO_ERROR,
    );
    while let Ok(control) = receiver.recv() {
        match control {
            Control::Stop => break,
            Control::SignedOut(session) => server
                .manager
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .session_ended(session, "the user signed out"),
        }
    }
    set_status(handle, SERVICE_STOP_PENDING, 0, NO_ERROR);
    server.stop();
    let _ = listener.join();
    let _ = watcher.join();
    log!("service stopped");
    set_status(handle, SERVICE_STOPPED, 0, NO_ERROR);
}

// Called by the service manager: --service
pub fn run() -> i32 {
    let name = wide(names::SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_ptr() as *mut u16, lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: ptr::null_mut(), lpServiceProc: None },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        eprintln!("this is the service of {}: {}", names::PRODUCT, error_message(last_error()));
        return 1;
    }
    0
}

// The service as the user, with fake tunnels, for the tests: until the process is ended
#[cfg(feature = "testing")]
pub fn run_console() -> i32 {
    log::init(log_path());
    log!("{} {}: test service started", names::PRODUCT, names::VERSION);
    let server = Server::new();
    {
        let server = server.clone();
        thread::spawn(move || server.watch());
    }
    server.listen();
    1
}
