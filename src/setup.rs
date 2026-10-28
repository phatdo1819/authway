// Where the MSI package installs the app, and the steps of the setup it can't do by itself: it runs this exe with
// --msi-... to end the app of every user before it changes the exe, start it again after, and remove the data of
// the app when it's removed, not updated

use std::fs;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_CANCELLED, ERROR_NO_TOKEN, ERROR_SERVICE_ALREADY_RUNNING, HANDLE, HWND,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{CheckTokenMembership, CreateWellKnownSid, WinLocalSystemSid};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken, WTS_CURRENT_SERVER_HANDLE,
    WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, StartServiceW, SC_HANDLE,
    SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcessId, GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW,
    TerminateProcess, WaitForSingleObject, CREATE_BREAKAWAY_FROM_JOB, CREATE_UNICODE_ENVIRONMENT, INFINITE,
    PROCESS_INFORMATION, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, STARTUPINFOW,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramFiles, ShellExecuteExW, ShellExecuteW, SEE_MASK_NOASYNC,
    SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::log;
use crate::names::{self, EXE_NAME, PRODUCT, SERVICE_NAME};
use crate::reg;
use crate::win::{error_message, exe_path, known_folder, last_error, last_error_message, wide, wide_path, Handle};

// the app logs out and turns its tunnels off before it quits
const QUIT_TIMEOUT: Duration = Duration::from_secs(15);

// the folder of the MSI package, which can't be changed
pub fn install_dir() -> PathBuf {
    known_folder(&FOLDERID_ProgramFiles).unwrap_or_else(|| PathBuf::from(r"C:\Program Files")).join(PRODUCT)
}

pub fn installed_exe() -> PathBuf {
    install_dir().join(EXE_NAME)
}

pub fn user_data_dir() -> PathBuf {
    known_folder(&FOLDERID_LocalAppData).unwrap_or_default().join(format!(
        "{}{}",
        PRODUCT,
        if cfg!(feature = "testing") { " test" } else { "" }
    ))
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase()
}

pub fn is_installed_copy() -> bool {
    same_path(&exe_path(), &installed_exe())
}

pub fn quote(argument: &str) -> String {
    format!("\"{}\"", argument)
}

// SYSTEM, as a deployment tool runs the commands: it has no Credential Manager of a user
pub fn is_system_account() -> bool {
    let mut sid = [0u8; 68];
    let mut size = sid.len() as u32;
    let mut member = 0;
    unsafe {
        CreateWellKnownSid(WinLocalSystemSid, ptr::null_mut(), sid.as_mut_ptr() as _, &mut size) != 0
            && CheckTokenMembership(ptr::null_mut(), sid.as_mut_ptr() as _, &mut member) != 0
            && member != 0
    }
}

pub const CANCELLED: &str = "cancelled";

// Runs this exe again as administrator and waits for it: its exit code, Err(CANCELLED) if the user said no
pub fn elevate(arguments: &str, owner: HWND) -> Result<u32, String> {
    let exe = wide_path(&exe_path());
    let arguments = wide(arguments);
    let verb = wide("runas");
    let mut info: SHELLEXECUTEINFOW = unsafe { zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.hwnd = owner;
    info.lpVerb = verb.as_ptr();
    info.lpFile = exe.as_ptr();
    info.lpParameters = arguments.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = last_error();
        return Err(if code == ERROR_CANCELLED { CANCELLED.to_string() } else { error_message(code) });
    }
    let process = Handle(info.hProcess);
    let mut code = 1u32;
    unsafe {
        WaitForSingleObject(process.0, INFINITE);
        GetExitCodeProcess(process.0, &mut code);
    }
    Ok(code)
}

// Starts an exe as the user who runs this one
pub fn launch(exe: &Path, arguments: &str) -> bool {
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            wide("open").as_ptr(),
            wide_path(exe).as_ptr(),
            wide(arguments).as_ptr(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    result as usize > 32
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn service_state(service: &ServiceHandle) -> Option<u32> {
    let mut status: SERVICE_STATUS = unsafe { zeroed() };
    if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
        return None;
    }
    Some(status.dwCurrentState)
}

fn wait_state(service: &ServiceHandle, state: u32, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if service_state(service) == Some(state) {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

// the users can: the MSI package gives them the right
pub fn start_service() -> Result<(), String> {
    let manager = ServiceHandle(unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) });
    if manager.0.is_null() {
        return Err(format!("can't open the services: {}", last_error_message()));
    }
    let service = ServiceHandle(unsafe {
        OpenServiceW(manager.0, wide(SERVICE_NAME).as_ptr(), SERVICE_START | SERVICE_QUERY_STATUS)
    });
    if service.0.is_null() {
        return Err(last_error_message());
    }
    if unsafe { StartServiceW(service.0, 0, ptr::null()) } == 0 && last_error() != ERROR_SERVICE_ALREADY_RUNNING {
        return Err(last_error_message());
    }
    wait_state(&service, SERVICE_RUNNING, Duration::from_secs(10));
    Ok(())
}

// The installed exe running as the app, in any session of Windows, with its session: never this process
fn running_apps() -> Vec<(u32, Handle)> {
    let target = installed_exe();
    let own = unsafe { GetCurrentProcessId() };
    let mut found = Vec::new();
    unsafe {
        let snapshot = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if !snapshot.is_valid() {
            return Vec::new();
        }
        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot.0, &mut entry) != 0;
        while more {
            if entry.th32ProcessID != own && crate::win::from_wide(&entry.szExeFile).eq_ignore_ascii_case(EXE_NAME) {
                found.push(entry.th32ProcessID);
            }
            more = Process32NextW(snapshot.0, &mut entry) != 0;
        }
    }
    let mut apps = Vec::new();
    for id in found {
        let process = Handle(unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, id)
        });
        let mut session = 0;
        if !process.is_valid() || unsafe { ProcessIdToSessionId(id, &mut session) } == 0 {
            continue;
        }
        let mut path = [0u16; 1024];
        let mut length = path.len() as u32;
        // the service runs in session 0, where nobody signs in
        if session != 0
            && unsafe { QueryFullProcessImageNameW(process.0, PROCESS_NAME_WIN32, path.as_mut_ptr(), &mut length) } != 0
            && same_path(&crate::win::path_from_wide(&path[..length as usize]), &target)
        {
            apps.push((session, process));
        }
    }
    apps
}

// The sessions of Windows, the ones without a user too
fn sessions() -> Vec<u32> {
    let mut list: *mut WTS_SESSION_INFOW = ptr::null_mut();
    let mut count = 0u32;
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut list, &mut count) } == 0 {
        log!("can't list the sessions: {}", last_error_message());
        return Vec::new();
    }
    let ids = unsafe { std::slice::from_raw_parts(list, count as usize) }.iter().map(|info| info.SessionId).collect();
    unsafe { WTSFreeMemory(list as _) };
    ids
}

// Starts the installed exe in a session, as the user signed in there: Ok(None) when nobody is. Only SYSTEM can.
fn run_in_session(session: u32, arguments: &str) -> Result<Option<Handle>, String> {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { WTSQueryUserToken(session, &mut token) } == 0 {
        return match last_error() {
            ERROR_NO_TOKEN => Ok(None),
            code => Err(error_message(code)),
        };
    }
    let token = Handle(token);
    let exe = installed_exe();
    let mut command = wide(&format!("{} {}", quote(&exe.display().to_string()), arguments));
    let desktop = wide(r"winsta0\default");
    let directory = wide_path(&install_dir());
    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    startup.lpDesktop = desktop.as_ptr() as *mut _;
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    unsafe {
        // the variables of the user, not of SYSTEM
        let mut environment: *mut core::ffi::c_void = ptr::null_mut();
        if CreateEnvironmentBlock(&mut environment, token.0, 0) == 0 {
            environment = ptr::null_mut();
        }
        let mut create = |flags| {
            CreateProcessAsUserW(
                token.0,
                wide_path(&exe).as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                CREATE_UNICODE_ENVIRONMENT | flags,
                environment,
                directory.as_ptr(),
                &startup,
                &mut info,
            ) != 0
        };
        // out of the job of the setup, which may end its processes when it's done
        let mut ok = create(CREATE_BREAKAWAY_FROM_JOB);
        if !ok && last_error() == ERROR_ACCESS_DENIED {
            ok = create(0);
        }
        let code = last_error();
        if !environment.is_null() {
            DestroyEnvironmentBlock(environment);
        }
        if !ok {
            return Err(error_message(code));
        }
        CloseHandle(info.hThread);
    }
    Ok(Some(Handle(info.hProcess)))
}

// --msi-stop-apps, as SYSTEM before the setup changes or removes the exe: the app of every user quits as if the user
// quit it, logged out and with its tunnels off; the ones that don't quit in time are ended
pub fn stop_apps() {
    let apps = running_apps();
    let mut sessions: Vec<u32> = apps.iter().map(|(session, _)| *session).collect();
    sessions.sort_unstable();
    sessions.dedup();
    // they quit at the same time
    let _quitting: Vec<Handle> = sessions
        .into_iter()
        .filter_map(|session| {
            run_in_session(session, "--quit")
                .map_err(|error| log!("can't ask the app of session {} to quit: {}", session, error))
                .ok()
                .flatten()
        })
        .collect();
    let deadline = Instant::now() + QUIT_TIMEOUT;
    for (session, process) in apps {
        let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u32;
        if unsafe { WaitForSingleObject(process.0, left) } == WAIT_OBJECT_0 {
            log!("the app of session {} quit", session);
        } else {
            log!("the app of session {} doesn't quit: it's ended", session);
            unsafe { TerminateProcess(process.0, 1) };
        }
    }
}

// --msi-start-apps, as SYSTEM once the app is installed or updated: it starts for every user signed in, as it does
// at the sign-in
pub fn start_apps() {
    let running: Vec<u32> = running_apps().into_iter().map(|(session, _)| session).collect();
    for session in sessions().into_iter().filter(|&session| session != 0 && !running.contains(&session)) {
        match run_in_session(session, "--startup") {
            Ok(Some(_)) => log!("the app started in session {}", session),
            Ok(None) => {}
            Err(error) => log!("can't start the app in session {}: {}", session, error),
        }
    }
}

// --msi-remove-data, as SYSTEM when the app is removed, not updated: the tunnels with their device keys, the logs
// and the driver, which stays while another app uses it
pub fn remove_data() {
    if let Ok(wireguard) = crate::wg::WireGuard::load() {
        let _ = wireguard.delete_driver();
    }
    // the keys are kept by Windows, out of the registry of the app
    for stored in crate::store::list() {
        crate::devkey::delete(&stored.name, &stored.id);
    }
    let _ = reg::delete_tree(reg::HKEY_LOCAL_MACHINE, &names::machine_key());
    let _ = fs::remove_dir_all(install_dir().join("log"));
}

// --msi-remove-user-data, as the user who removes the app: the settings and passwords of the app, and its log
pub fn remove_user_data() {
    crate::settings::delete_user_settings();
    crate::creds::delete_all();
    let _ = fs::remove_dir_all(user_data_dir());
}
