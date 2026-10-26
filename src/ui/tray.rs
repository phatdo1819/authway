// The icon next to the clock and what the app knows of the tunnels: it asks the service for them, turns them on
// and off, and logs in to the servers that require it, then watches the session

use std::cell::RefCell;
use std::mem::{size_of, zeroed};
use std::ptr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, HWND, LPARAM, LRESULT, POINT, RECT, WAIT_OBJECT_0, WPARAM};
use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateMutexW, OpenEventW, OpenMutexW, SetEvent, WaitForMultipleObjects, EVENT_MODIFY_STATE, INFINITE,
    SYNCHRONIZATION_SYNCHRONIZE,
};
use windows_sys::Win32::UI::Controls::{InitCommonControlsEx, ICC_STANDARD_CLASSES, ICC_WIN95_CLASSES, INITCOMMONCONTROLSEX};
use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_INFO, NIIF_WARNING, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NIN_BALLOONUSERCLICK, NIN_SELECT, NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, GetCursorPos, KillTimer, LoadImageW,
    ENDSESSION_CLOSEAPP,
    PostMessageW, RegisterClassExW, RegisterWindowMessageW, SetForegroundWindow, SetMenuDefaultItem,
    SetTimer, TrackPopupMenuEx, HICON, HMENU, IMAGE_ICON, LR_DEFAULTCOLOR, MB_ICONERROR, MF_GRAYED, MF_POPUP,
    MF_SEPARATOR, MF_STRING, SM_CXSMICON, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_CONTEXTMENU, WM_ENDSESSION,
    WM_NULL, WM_TIMER, WNDCLASSEXW, WS_OVERLAPPED,
};

use super::connect::{ConnectWindow, OTP_LENGTH};
use super::details::{self, DetailsWindow};
use super::{flows, instance, message_box, message_loop, time, Startup, WM_APP_EVENT, WM_APP_IMPORT, WM_APP_QUIT, WM_APP_SHOW, WM_APP_TRAY};
use crate::api::{self, ApiResult, Page};
use crate::conf::IpNet;
use crate::creds;
use crate::ipc::{self, CallError, Request, Response, TunnelInfo};
use crate::log;
use crate::names::{self, PRODUCT, VERSION};
use crate::settings;
use crate::setup;
use crate::strings;
use crate::win::{last_error, unix_now, wide};

const CLASS: &str = "AuthwayTray";
const TIMER: usize = 1;
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;
const POLL_LOGGED_IN: Duration = Duration::from_secs(20);
const POLL_NOT_LOGGED_IN: Duration = Duration::from_secs(30);
const POLL_REFUSED: Duration = Duration::from_secs(60);
const POLL_NOT_REQUIRED: Duration = Duration::from_secs(300);
const RETRY_UNREACHABLE: Duration = Duration::from_secs(10);
// right after the tunnel comes up, the login page is asked every second
const RETRY_CONNECTING: Duration = Duration::from_secs(1);
const CONNECTING_TIME: Duration = Duration::from_secs(30);
const LIST_ACTIVE: Duration = Duration::from_secs(2);
const LIST_IDLE: Duration = Duration::from_secs(10);
// seconds without a handshake for "the server doesn't answer"
const NO_HANDSHAKE: u64 = 15;
const OLD_HANDSHAKE: u64 = 300;
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Session {
    Off,
    Checking,
    Unreachable,
    NotRequired,
    NeedLogin,
    LoggedIn,
    Blocked,
    NoUser,
}

// What the app knows of a tunnel of the service, and of its session on the login page
pub struct Tunnel {
    pub info: TunnelInfo,
    pub page: Option<Page>,
    pub session: Session,
    pub server_name: String,
    pub otp_required: bool,
    // whether a status said it
    pub otp_known: bool,
    pub user: String,
    pub expires: u64,
    pub next_check: Instant,
    pub busy: bool,
    // changes when the tunnel goes down: the answers asked before are dropped
    pub generation: u32,
    // the window opened by itself in this connection
    pub prompted: bool,
    pub logged_out: bool,
    pub searched: bool,
    // the balloon "connected" was shown in this connection
    pub announced: bool,
    pub connecting_since: Option<Instant>,
    // cancelled while it was turning on: off as soon as it's on
    pub abandon: bool,
    pub stopping: bool,
    // the last turn on or off asked here: the lists asked before it are older
    pub changed_at: Instant,
    pub up_at: Option<Instant>,
    pub error: Option<String>,
}

impl Tunnel {
    pub(crate) fn new(name: &str) -> Tunnel {
        let now = Instant::now();
        Tunnel {
            info: TunnelInfo { name: name.to_string(), ..TunnelInfo::default() },
            page: None,
            session: Session::Off,
            server_name: String::new(),
            otp_required: true,
            otp_known: false,
            user: String::new(),
            expires: 0,
            next_check: now,
            busy: false,
            generation: 0,
            prompted: false,
            logged_out: false,
            searched: false,
            announced: false,
            connecting_since: None,
            abandon: false,
            stopping: false,
            changed_at: now - Duration::from_secs(3600),
            up_at: None,
            error: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.info.name
    }

    // the name of the server for the user
    pub fn title(&self) -> String {
        if !self.server_name.is_empty() {
            return self.server_name.clone();
        }
        self.info.server.clone().filter(|server| !server.is_empty()).unwrap_or_else(|| self.info.name.clone())
    }

    fn endpoint_host(&self) -> String {
        let endpoint = &self.info.endpoint;
        let host = endpoint.rsplit_once(':').map(|(host, _)| host).unwrap_or(endpoint);
        host.trim_start_matches('[').trim_end_matches(']').to_string()
    }

    // the one of the configuration, or the one found on an earlier connection
    fn set_page(&mut self) {
        self.page = match self.info.login.as_deref().and_then(Page::parse) {
            Some(page) => Some(page),
            None => settings::found_page(&self.info.name),
        };
    }

    fn on_up(&mut self, now: Instant) {
        self.session = if self.page.is_some() { Session::Checking } else { Session::NotRequired };
        self.next_check = now;
        self.generation += 1;
        self.prompted = false;
        self.logged_out = false;
        self.searched = false;
        self.announced = false;
        self.connecting_since = None;
        self.error = None;
        self.up_at = Some(now);
    }

    fn set_off(&mut self) {
        self.session = Session::Off;
        self.generation += 1;
        self.prompted = false;
        self.logged_out = false;
        self.user.clear();
        self.expires = 0;
        self.searched = false;
        self.announced = false;
        self.up_at = None;
    }

    pub fn needs_login(&self) -> bool {
        self.info.up && self.session == Session::NeedLogin
    }

    fn connecting(&self) -> bool {
        self.connecting_since.is_some() && !self.info.up
    }

    fn no_answer(&self) -> bool {
        let now = unix_now();
        self.info.up
            && ((self.info.handshake == 0 && now.saturating_sub(self.info.since) > NO_HANDSHAKE)
                || (self.info.handshake > 0 && now.saturating_sub(self.info.handshake) > OLD_HANDSHAKE))
    }

    pub fn describe(&self) -> String {
        if self.stopping {
            return strings::STATE_DISCONNECTING.to_string();
        }
        if !self.info.up {
            return if self.connecting() {
                strings::STATE_CONNECTING
            } else if self.error.is_some() {
                strings::STATE_FAILED
            } else {
                strings::STATE_OFF
            }
            .to_string();
        }
        if self.no_answer() {
            return strings::STATE_NO_ANSWER.to_string();
        }
        if self.page.is_none() {
            return if self.info.handshake > 0 { strings::STATE_CONNECTED } else { strings::STATE_CONNECTING }.to_string();
        }
        match self.session {
            Session::Off | Session::Checking => strings::STATE_CONNECTING.to_string(),
            Session::Unreachable => strings::STATE_UNREACHABLE.to_string(),
            Session::NotRequired => strings::STATE_CONNECTED.to_string(),
            Session::NeedLogin => strings::STATE_NEED_LOGIN.to_string(),
            Session::LoggedIn => strings::state_logged_in(&self.user, &time::format_local(self.expires)),
            Session::Blocked => strings::STATE_BLOCKED.to_string(),
            Session::NoUser => strings::STATE_NO_USER.to_string(),
        }
    }

    // what the tray shows first, higher first
    fn rank(&self) -> Icon {
        if self.stopping || self.connecting() {
            return Icon::Attention;
        }
        if !self.info.up {
            return Icon::Idle;
        }
        if self.no_answer() {
            return Icon::Attention;
        }
        if self.page.is_none() {
            return if self.info.handshake > 0 { Icon::Connected } else { Icon::Attention };
        }
        match self.session {
            Session::Blocked | Session::NoUser => Icon::Refused,
            Session::LoggedIn | Session::NotRequired => Icon::Connected,
            _ => Icon::Attention,
        }
    }
}

// the icons of the tray, in the order of build.rs, and of importance
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Icon {
    Idle = 0,
    Connected = 1,
    Attention = 2,
    Refused = 3,
}

impl Icon {
    fn resource(self) -> u16 {
        match self {
            Icon::Idle => 2,
            Icon::Attention => 3,
            Icon::Connected => 4,
            Icon::Refused => 5,
        }
    }
}

pub enum Event {
    List { requested: Instant, result: Result<Response, CallError> },
    Up { name: String, result: Result<Response, CallError> },
    Down { name: String, result: Result<Response, CallError> },
    Status { name: String, generation: u32, result: ApiResult },
    Login { name: String, generation: u32, result: ApiResult, username: String, password: String, remember: bool },
    Found { name: String, generation: u32, page: Option<Page> },
}

pub enum Command {
    Connect(String),
    Disconnect(String),
    LogIn(String),
    Import,
    Remove(String),
    Details(String),
    AppLog,
    ServiceLog,
    StartService,
    Quit,
}

#[derive(PartialEq, Eq)]
enum ServiceState {
    Unknown,
    Running,
    Unavailable,
    Failed,
}

pub struct App {
    pub hwnd: HWND,
    sender: Sender<Event>,
    receiver: Receiver<Event>,
    tunnels: Vec<Tunnel>,
    can_manage: bool,
    service: ServiceState,
    listing: bool,
    next_list: Instant,
    windows: Vec<ConnectWindow>,
    details: Vec<DetailsWindow>,
    icons: [HICON; 4],
    shown: Option<(Icon, String)>,
    balloon: Option<String>,
    exiting: bool,
    pending_connect: Option<String>,
    startup: Option<Startup>,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

// The App, if it's free: None while a call on it is running, for the messages that it causes itself
pub fn with_app<R>(action: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.with(|cell| {
        let mut guard = cell.try_borrow_mut().ok()?;
        let app = guard.as_mut()?;
        Some(action(app))
    })
}

pub fn error_message(result: &ApiResult) -> String {
    if !result.reached() {
        return strings::ERROR_UNREACHABLE.to_string();
    }
    match result.status {
        401 => strings::ERROR_CREDENTIALS.to_string(),
        // nginx answers too many requests without retry_after
        429 => strings::error_attempts(((result.get_int("retry_after", 60) + 59) / 60).max(1)),
        403 => match result.error() {
            "blocked" => strings::ERROR_BLOCKED.to_string(),
            "no_user" => strings::ERROR_NO_USER.to_string(),
            _ => strings::ERROR_FORBIDDEN.to_string(),
        },
        _ => strings::ERROR_FAILED.to_string(),
    }
}

fn call_message(error: &CallError) -> String {
    match error {
        CallError::Unavailable => strings::service_unavailable(),
        CallError::Failed(message) => message.clone(),
    }
}

fn outcome(result: &Result<Response, CallError>) -> Result<(), String> {
    match result {
        Ok(response) if response.ok => Ok(()),
        Ok(response) => Err(response.message().to_string()),
        Err(error) => Err(call_message(error)),
    }
}

fn copy_wide(target: &mut [u16], text: &str) {
    let text: Vec<u16> = text.encode_utf16().take(target.len() - 1).collect();
    target[..text.len()].copy_from_slice(&text);
    target[text.len()] = 0;
}

fn nets(texts: &[String]) -> Vec<IpNet> {
    texts.iter().filter_map(|text| IpNet::parse(text)).collect()
}

impl App {
    fn new(hwnd: HWND, startup: Startup) -> App {
        let (sender, receiver) = mpsc::channel();
        let size = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, GetDpiForSystem()) };
        let load = |icon: Icon| unsafe {
            LoadImageW(instance(), icon.resource() as usize as _, IMAGE_ICON, size, size, LR_DEFAULTCOLOR) as HICON
        };
        let now = Instant::now();
        App {
            hwnd,
            sender,
            receiver,
            tunnels: Vec::new(),
            can_manage: false,
            service: ServiceState::Unknown,
            listing: false,
            next_list: now,
            windows: Vec::new(),
            details: Vec::new(),
            icons: [load(Icon::Idle), load(Icon::Connected), load(Icon::Attention), load(Icon::Refused)],
            shown: None,
            balloon: None,
            exiting: false,
            pending_connect: None,
            startup: Some(startup),
        }
    }

    fn start(&mut self) {
        self.add_icon();
        unsafe { SetTimer(self.hwnd, TIMER, 1000, None) };
        self.list();
    }

    fn spawn(&self, work: impl FnOnce() -> Event + Send + 'static) {
        let sender = self.sender.clone();
        let hwnd = self.hwnd as usize;
        thread::spawn(move || {
            let event = work();
            if sender.send(event).is_ok() {
                unsafe { PostMessageW(hwnd as HWND, WM_APP_EVENT, 0, 0) };
            }
        });
    }

    fn tunnel_index(&self, name: &str) -> Option<usize> {
        self.tunnels.iter().position(|tunnel| tunnel.info.name == name)
    }

    fn window_index(&self, name: &str) -> Option<usize> {
        self.windows.iter().position(|window| window.tunnel == name)
    }

    fn window_of(&self, hwnd: HWND) -> Option<String> {
        self.windows.iter().find(|window| window.hwnd == hwnd).map(|window| window.tunnel.clone())
    }

    pub fn tunnel_names(&self) -> Vec<String> {
        self.tunnels.iter().map(|tunnel| tunnel.info.name.clone()).collect()
    }

    // the tray

    fn notify_data(&self) -> NOTIFYICONDATAW {
        let mut data: NOTIFYICONDATAW = unsafe { zeroed() };
        data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = self.hwnd;
        data.uID = 1;
        data
    }

    // also when the taskbar comes back, after explorer restarts
    pub fn add_icon(&mut self) {
        let (icon, tip) = self.summary();
        let mut data = self.notify_data();
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        data.uCallbackMessage = WM_APP_TRAY;
        data.hIcon = self.icons[icon as usize];
        copy_wide(&mut data.szTip, &tip);
        unsafe {
            Shell_NotifyIconW(NIM_ADD, &data);
            data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &data);
        }
        self.shown = Some((icon, tip));
    }

    pub fn remove_icon(&mut self) {
        let data = self.notify_data();
        unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
    }

    fn summary(&self) -> (Icon, String) {
        if self.service == ServiceState::Unavailable {
            return (Icon::Idle, format!("{}: {}", PRODUCT, strings::MENU_SERVICE_DOWN));
        }
        match self.tunnels.iter().max_by_key(|tunnel| tunnel.rank()) {
            Some(tunnel) if tunnel.rank() != Icon::Idle => (tunnel.rank(), format!("{}: {}", tunnel.name(), tunnel.describe())),
            _ => (Icon::Idle, format!("{}: {}", PRODUCT, strings::STATE_OFF)),
        }
    }

    fn update_icon(&mut self) {
        let (icon, tip) = self.summary();
        if self.shown.as_ref() == Some(&(icon, tip.clone())) {
            return;
        }
        let mut data = self.notify_data();
        data.uFlags = NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        data.hIcon = self.icons[icon as usize];
        copy_wide(&mut data.szTip, &tip);
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
        self.shown = Some((icon, tip));
    }

    fn notify(&mut self, text: &str, warning: bool, tunnel: Option<&str>) {
        let mut data = self.notify_data();
        data.uFlags = NIF_INFO;
        copy_wide(&mut data.szInfo, text);
        copy_wide(&mut data.szInfoTitle, PRODUCT);
        data.dwInfoFlags = if warning { NIIF_WARNING } else { NIIF_INFO };
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
        self.balloon = tunnel.map(str::to_string);
    }

    // the events of the other threads

    pub fn drain(&mut self) {
        let events: Vec<Event> = self.receiver.try_iter().collect();
        for event in events {
            if self.exiting {
                return;
            }
            match event {
                Event::List { requested, result } => self.on_list(requested, result),
                Event::Up { name, result } => self.on_up(&name, result),
                Event::Down { name, result } => self.on_down(&name, result),
                Event::Status { name, generation, result } => self.on_status(&name, generation, result),
                Event::Login { name, generation, result, username, password, remember } => {
                    self.on_login(&name, generation, result, &username, password, remember)
                }
                Event::Found { name, generation, page } => self.on_found(&name, generation, page),
            }
        }
        self.update_icon();
    }

    fn list(&mut self) {
        self.listing = true;
        let requested = Instant::now();
        self.spawn(move || Event::List { requested, result: ipc::call(&Request::List) });
    }

    pub fn list_soon(&mut self) {
        self.next_list = Instant::now();
    }

    pub fn tick(&mut self) {
        self.drain();
        if self.exiting {
            return;
        }
        let now = Instant::now();
        if !self.listing && now >= self.next_list {
            self.list();
        }
        let mut checks = Vec::new();
        let mut searches = Vec::new();
        let mut announce = Vec::new();
        for tunnel in &mut self.tunnels {
            if !tunnel.info.up || tunnel.stopping {
                continue;
            }
            match tunnel.page {
                Some(page) => {
                    if !tunnel.busy && now >= tunnel.next_check {
                        tunnel.busy = true;
                        checks.push((tunnel.info.name.clone(), tunnel.generation, page));
                    }
                }
                None => {
                    if !tunnel.searched && tunnel.info.handshake > 0 {
                        tunnel.searched = true;
                        let candidates = api::candidates_of(&nets(&tunnel.info.addresses), &nets(&tunnel.info.routes));
                        if !candidates.is_empty() {
                            searches.push((tunnel.info.name.clone(), tunnel.generation, candidates));
                        }
                    }
                    if !tunnel.announced && tunnel.info.handshake > 0 {
                        tunnel.announced = true;
                        announce.push(tunnel.title());
                    }
                }
            }
        }
        for (name, generation, page) in checks {
            self.spawn(move || Event::Status { name, generation, result: api::status(&page) });
        }
        for (name, generation, candidates) in searches {
            log!("{}: looking for the login page at {:?}", name, candidates);
            self.spawn(move || Event::Found {
                name,
                generation,
                page: api::discover(&candidates, api::DEFAULT_PORT, api::WEB_PORT),
            });
        }
        for title in announce {
            self.notify(&strings::notice_connected(&title), false, None);
        }
        self.update_details();
        self.update_icon();
    }

    fn on_list(&mut self, requested: Instant, result: Result<Response, CallError>) {
        self.listing = false;
        let now = Instant::now();
        match result {
            Err(CallError::Unavailable) => {
                if self.service != ServiceState::Unavailable {
                    log!("the service isn't running");
                }
                self.service = ServiceState::Unavailable;
                self.merge(Vec::new(), now, true);
            }
            Err(CallError::Failed(message)) => {
                if self.service != ServiceState::Failed {
                    log!("can't list the tunnels: {}", message);
                }
                self.service = ServiceState::Failed;
            }
            Ok(response) if !response.ok => log!("can't list the tunnels: {}", response.message()),
            Ok(response) => {
                if self.service != ServiceState::Running {
                    log!("the service is running");
                }
                self.service = ServiceState::Running;
                self.can_manage = response.can_manage;
                self.merge(response.tunnels, requested, false);
            }
        }
        let active = self.tunnels.iter().any(|tunnel| tunnel.info.up || tunnel.connecting() || tunnel.stopping);
        self.next_list = now + if active { LIST_ACTIVE } else { LIST_IDLE };
        if let Some(startup) = self.startup.take() {
            self.started(startup);
        }
        if let Some(name) = self.pending_connect.take() {
            self.connect(&name);
        }
    }

    // The first list: what to show, depending on who started the app
    fn started(&mut self, startup: Startup) {
        if self.service == ServiceState::Unavailable {
            self.notify(&strings::service_unavailable(), true, None);
            return;
        }
        if self.tunnels.is_empty() {
            self.notify(&strings::notice_welcome(), false, None);
            return;
        }
        if startup == Startup::Normal {
            self.show_from_user();
        }
    }

    fn merge(&mut self, infos: Vec<TunnelInfo>, requested: Instant, service_gone: bool) {
        let now = Instant::now();
        let mut previous = std::mem::take(&mut self.tunnels);
        let mut closed = Vec::new();
        let mut notices = Vec::new();
        for info in infos {
            let position = previous.iter().position(|tunnel| tunnel.info.name == info.name);
            let mut tunnel = match position {
                Some(position) => previous.remove(position),
                None => Tunnel::new(&info.name),
            };
            let was_up = tunnel.info.up;
            let login_changed = position.is_none() || tunnel.info.login != info.login;
            let (up, since) = (tunnel.info.up, tunnel.info.since);
            tunnel.info = info;
            // a list asked before the last turn on or off here doesn't know of it
            if requested < tunnel.changed_at {
                tunnel.info.up = up;
                tunnel.info.since = since;
            }
            if login_changed {
                tunnel.set_page();
            }
            if !was_up && tunnel.info.up {
                tunnel.on_up(now);
            }
            if was_up && !tunnel.info.up {
                if !tunnel.stopping {
                    log!("{}: disconnected by the service", tunnel.name());
                    if tunnel.announced {
                        notices.push(strings::notice_disconnected(&tunnel.title()));
                    }
                }
                tunnel.stopping = false;
                tunnel.set_off();
                closed.push(tunnel.info.name.clone());
            }
            self.tunnels.push(tunnel);
        }
        if service_gone {
            // the tunnels went with the service
            for mut tunnel in previous.drain(..) {
                if tunnel.info.up {
                    tunnel.set_off();
                    tunnel.info.up = false;
                    closed.push(tunnel.info.name.clone());
                }
                tunnel.connecting_since = None;
                tunnel.stopping = false;
                self.tunnels.push(tunnel);
            }
        }
        for tunnel in previous {
            closed.push(tunnel.info.name);
        }
        for name in closed {
            self.close_window(&name);
        }
        for notice in notices {
            self.notify(&notice, false, None);
        }
    }

    fn on_up(&mut self, name: &str, result: Result<Response, CallError>) {
        let Some(index) = self.tunnel_index(name) else { return };
        let now = Instant::now();
        let window = self.window_index(name);
        let tunnel = &mut self.tunnels[index];
        tunnel.connecting_since = None;
        match outcome(&result) {
            Ok(()) => {
                log!("{}: on", name);
                tunnel.info.up = true;
                tunnel.info.since = unix_now();
                tunnel.info.handshake = 0;
                tunnel.changed_at = now;
                tunnel.on_up(now);
                let abandon = std::mem::take(&mut tunnel.abandon);
                self.next_list = now;
                if abandon {
                    self.disconnect(name);
                }
            }
            Err(message) => {
                log!("{}: can't connect: {}", name, message);
                tunnel.error = Some(message.clone());
                if std::mem::take(&mut tunnel.abandon) {
                    return;
                }
                let title = tunnel.title();
                match window {
                    Some(window) => {
                        let window = &mut self.windows[window];
                        window.pending_submit = false;
                        window.set_busy(false);
                        window.set_error(Some(&strings::error_connect(&message)));
                    }
                    None => self.notify(&strings::notice_failed(&title, &message), true, None),
                }
            }
        }
    }

    fn on_down(&mut self, name: &str, result: Result<Response, CallError>) {
        let Some(index) = self.tunnel_index(name) else { return };
        let tunnel = &mut self.tunnels[index];
        tunnel.stopping = false;
        match outcome(&result) {
            Ok(()) => {
                log!("{}: off", name);
                tunnel.info.up = false;
                tunnel.changed_at = Instant::now();
                tunnel.set_off();
            }
            Err(message) => {
                log!("{}: can't disconnect: {}", name, message);
                let text = strings::notice_failed(&tunnel.title(), &message);
                self.notify(&text, true, None);
            }
        }
        self.list_soon();
    }

    fn on_status(&mut self, name: &str, generation: u32, result: ApiResult) {
        let Some(index) = self.tunnel_index(name) else { return };
        let tunnel = &mut self.tunnels[index];
        tunnel.busy = false;
        if generation != tunnel.generation || !tunnel.info.up || tunnel.stopping {
            return;
        }
        self.apply_status(index, result);
    }

    fn apply_status(&mut self, index: usize, result: ApiResult) {
        let now = Instant::now();
        let name = self.tunnels[index].info.name.clone();
        let window = self.window_index(&name);
        let mut close_window = false;
        let mut prompt: Option<Option<&'static str>> = None;
        let mut balloon: Option<(String, bool)> = None;
        {
            let tunnel = &mut self.tunnels[index];
            let previous = tunnel.session;
            let fast = window.is_some() || tunnel.up_at.is_some_and(|at| now.duration_since(at) < CONNECTING_TIME);
            if result.status == 403 && result.error() == "forbidden" {
                // the server doesn't require the login, or the tunnel goes to another server
                if previous != Session::NotRequired {
                    log!("{}: no login needed", name);
                }
                tunnel.session = Session::NotRequired;
                tunnel.next_check = now + POLL_NOT_REQUIRED;
                close_window = true;
                if !tunnel.announced {
                    tunnel.announced = true;
                    balloon = Some((strings::notice_connected(&tunnel.title()), false));
                }
            } else if result.status != 200 || !result.has("authenticated") {
                if previous != Session::Unreachable {
                    log!("{}: no answer from the login page: {}", name, result);
                }
                tunnel.session = Session::Unreachable;
                tunnel.next_check = now + if fast { RETRY_CONNECTING } else { RETRY_UNREACHABLE };
            } else {
                let server = result.get_str("server");
                if !server.is_empty() {
                    tunnel.server_name = server.to_string();
                }
                tunnel.otp_required = result.get_bool("otp_required");
                tunnel.otp_known = true;
                if result.get_bool("authenticated") {
                    set_logged_in(tunnel, result.get_str("user"), result.get_str("expires"), now);
                    close_window = true;
                    if !tunnel.announced {
                        tunnel.announced = true;
                        let until = time::format_local(tunnel.expires);
                        balloon = Some((strings::notice_logged_in(&tunnel.title(), &tunnel.user, &until), false));
                    }
                } else if result.get_bool("blocked") || result.get_bool("no_user") {
                    let (state, text) = if result.get_bool("blocked") {
                        (Session::Blocked, strings::ERROR_BLOCKED)
                    } else {
                        (Session::NoUser, strings::ERROR_NO_USER)
                    };
                    if previous != state {
                        log!("{}: {:?}", name, state);
                        if window.is_none() {
                            balloon = Some((text.to_string(), true));
                        }
                    }
                    tunnel.session = state;
                    tunnel.next_check = now + POLL_REFUSED;
                } else {
                    tunnel.session = Session::NeedLogin;
                    tunnel.next_check = now + POLL_NOT_LOGGED_IN;
                    let mut notice = None;
                    if previous == Session::LoggedIn {
                        // expired, or ended by the firewall: another public IP, no handshake for a while, a copy...
                        log!("{}: the session ended", name);
                        notice = Some(strings::NOTICE_SESSION_ENDED);
                        tunnel.prompted = false;
                        tunnel.announced = false;
                    } else if previous != Session::NeedLogin {
                        log!("{}: not logged in", name);
                    }
                    if window.is_none() && !tunnel.prompted && !tunnel.logged_out {
                        tunnel.prompted = true;
                        prompt = Some(notice);
                    }
                }
            }
        }
        let mut submit = false;
        if let Some(window) = window.filter(|_| !close_window) {
            let tunnel = &self.tunnels[index];
            let window = &mut self.windows[window];
            match tunnel.session {
                Session::NeedLogin => {
                    window.set_heading(&tunnel.title());
                    window.set_otp_required(tunnel.otp_required);
                    window.set_hint(if tunnel.otp_required { strings::LOGIN_HINT_OTP } else { strings::LOGIN_HINT });
                    if window.pending_submit {
                        submit = true;
                    } else {
                        window.set_error(None);
                    }
                }
                Session::Blocked => window.set_error(Some(strings::ERROR_BLOCKED)),
                Session::NoUser => window.set_error(Some(strings::ERROR_NO_USER)),
                Session::Unreachable if tunnel.no_answer() => window.set_error(Some(strings::ERROR_NO_ANSWER)),
                _ => {}
            }
        }
        if close_window {
            self.close_window(&name);
        }
        if let Some(notice) = prompt {
            self.show_login(&name, notice);
        }
        if let Some((text, warning)) = balloon {
            self.notify(&text, warning, Some(&name));
        }
        if submit {
            self.submit_tunnel(&name);
        }
    }

    fn on_found(&mut self, name: &str, generation: u32, page: Option<Page>) {
        let Some(index) = self.tunnel_index(name) else { return };
        let tunnel = &mut self.tunnels[index];
        let Some(page) = page else {
            log!("{}: no login page", name);
            return;
        };
        if generation != tunnel.generation || tunnel.page.is_some() {
            return;
        }
        log!("{}: found the login page {}", name, page);
        settings::set_found_page(name, Some(&page));
        tunnel.page = Some(page);
        tunnel.session = Session::Checking;
        tunnel.next_check = Instant::now();
    }

    // the user

    pub fn connect(&mut self, name: &str) {
        let Some(index) = self.tunnel_index(name) else {
            // just added: once the service lists it
            self.pending_connect = Some(name.to_string());
            self.list_soon();
            return;
        };
        let tunnel = &self.tunnels[index];
        if tunnel.stopping {
            return;
        }
        if tunnel.info.up {
            if tunnel.page.is_some() && tunnel.session != Session::LoggedIn && tunnel.session != Session::NotRequired {
                self.show_login(name, None);
            }
            return;
        }
        let has_page = tunnel.page.is_some();
        if tunnel.connecting_since.is_none() {
            self.start_up(index);
        }
        if has_page {
            self.show_login(name, None);
        }
    }

    fn start_up(&mut self, index: usize) {
        let now = Instant::now();
        let tunnel = &mut self.tunnels[index];
        tunnel.connecting_since = Some(now);
        tunnel.abandon = false;
        tunnel.error = None;
        tunnel.changed_at = now;
        let name = tunnel.info.name.clone();
        log!("{}: connecting", name);
        self.next_list = now + LIST_ACTIVE;
        self.spawn(move || {
            let result = ipc::call(&Request::Up { name: name.clone() });
            Event::Up { name, result }
        });
        self.update_icon();
    }

    // with the logout first, so the session of the firewall ends at once
    pub fn disconnect(&mut self, name: &str) {
        self.close_window(name);
        let Some(index) = self.tunnel_index(name) else { return };
        let tunnel = &mut self.tunnels[index];
        if tunnel.stopping {
            return;
        }
        if tunnel.connecting() {
            tunnel.abandon = true;
            return;
        }
        if !tunnel.info.up {
            return;
        }
        tunnel.stopping = true;
        tunnel.changed_at = Instant::now();
        let page = if tunnel.session == Session::LoggedIn { tunnel.page } else { None };
        let name = name.to_string();
        log!("{}: disconnecting", name);
        self.spawn(move || {
            if let Some(page) = page {
                let result = api::logout(&page, Some(LOGOUT_TIMEOUT));
                if result.status != 200 {
                    log!("{}: can't log out: {}", name, result);
                }
            }
            let result = ipc::call(&Request::Down { name: name.clone() });
            Event::Down { name, result }
        });
        self.update_icon();
    }

    pub fn show_login(&mut self, name: &str, notice: Option<&str>) {
        if let Some(window) = self.window_index(name) {
            let window = &mut self.windows[window];
            if notice.is_some() {
                window.set_notice(notice);
            }
            window.activate();
            return;
        }
        let Some(index) = self.tunnel_index(name) else { return };
        let tunnel = &self.tunnels[index];
        let Some(page) = tunnel.page else { return };
        let saved = creds::read(&page);
        let hint = if tunnel.needs_login() {
            if tunnel.otp_required { strings::LOGIN_HINT_OTP.to_string() } else { strings::LOGIN_HINT.to_string() }
        } else {
            strings::login_connecting(&tunnel.endpoint_host())
        };
        let refused = match tunnel.session {
            Session::Blocked => Some(strings::ERROR_BLOCKED),
            Session::NoUser => Some(strings::ERROR_NO_USER),
            _ => None,
        };
        let window = ConnectWindow::open(
            name,
            &tunnel.title(),
            &hint,
            &saved,
            settings::can_remember_password(),
            tunnel.otp_required,
            notice,
        );
        if let Some(mut window) = window {
            window.set_error(refused);
            self.windows.push(window);
        }
    }

    fn close_window(&mut self, name: &str) {
        if let Some(index) = self.window_index(name) {
            // the window goes when dropped
            self.windows.remove(index);
        }
    }

    pub fn submit(&mut self, hwnd: HWND) {
        if let Some(name) = self.window_of(hwnd) {
            self.submit_tunnel(&name);
        }
    }

    fn submit_tunnel(&mut self, name: &str) {
        let (Some(window), Some(index)) = (self.window_index(name), self.tunnel_index(name)) else { return };
        let values = self.windows[window].values();
        let tunnel = &self.tunnels[index];
        let ready = tunnel.needs_login();
        let missing_otp = tunnel.otp_required && values.code.len() != OTP_LENGTH && (ready || tunnel.otp_known);
        let restart = !tunnel.info.up && !tunnel.connecting() && !tunnel.stopping;
        let window_ref = &mut self.windows[window];
        if values.username.is_empty() || values.password.is_empty() || missing_otp {
            window_ref.pending_submit = false;
            window_ref.set_busy(false);
            let text = if missing_otp && !values.username.is_empty() && !values.password.is_empty() {
                strings::ERROR_MISSING_OTP
            } else {
                strings::ERROR_MISSING
            };
            window_ref.set_error(Some(text));
            return;
        }
        window_ref.set_error(None);
        if !ready {
            // still connecting: the login goes as soon as the login page answers
            window_ref.pending_submit = true;
            window_ref.set_busy(true);
            if restart {
                self.start_up(index);
            }
            return;
        }
        let Some(page) = tunnel.page else { return };
        window_ref.pending_submit = false;
        window_ref.set_busy(true);
        let generation = tunnel.generation;
        let code = if tunnel.otp_required { values.code } else { String::new() };
        let name = name.to_string();
        let (username, password, remember) = (values.username, values.password, values.remember);
        self.spawn(move || {
            let result = api::login(&page, &username, &password, &code);
            Event::Login { name, generation, result, username, password, remember }
        });
    }

    fn on_login(&mut self, name: &str, generation: u32, result: ApiResult, username: &str, password: String, remember: bool) {
        let Some(index) = self.tunnel_index(name) else { return };
        let window = self.window_index(name);
        let now = Instant::now();
        if result.status == 200 {
            let tunnel = &mut self.tunnels[index];
            if let Some(page) = tunnel.page {
                let password = if remember && settings::can_remember_password() { Some(password.as_str()) } else { None };
                if !creds::save(&page, username, password) {
                    log!("{}: can't save the username in the Credential Manager", name);
                }
            }
            if generation == tunnel.generation && tunnel.info.up {
                set_logged_in(tunnel, result.get_str("user"), result.get_str("expires"), now);
                tunnel.announced = true;
                let until = time::format_local(tunnel.expires);
                let text = strings::notice_logged_in(&tunnel.title(), &tunnel.user, &until);
                self.close_window(name);
                self.notify(&text, false, None);
            } else {
                self.close_window(name);
            }
            return;
        }
        log!("{}: the login failed: {}", name, result);
        if let Some(window) = window {
            let window = &mut self.windows[window];
            window.set_busy(false);
            window.set_error(Some(&error_message(&result)));
            window.clear_code();
        }
        if result.status == 403 && (result.error() == "blocked" || result.error() == "no_user") {
            let tunnel = &mut self.tunnels[index];
            tunnel.session = if result.error() == "blocked" { Session::Blocked } else { Session::NoUser };
            tunnel.next_check = now + POLL_REFUSED;
        }
    }

    // the window is the connection: closing it disconnects
    pub fn cancel(&mut self, hwnd: HWND) {
        let Some(name) = self.window_of(hwnd) else { return };
        self.close_window(&name);
        if let Some(index) = self.tunnel_index(&name) {
            let tunnel = &self.tunnels[index];
            if tunnel.info.up || tunnel.connecting() {
                self.disconnect(&name);
            }
        }
    }

    pub fn code_changed(&mut self, hwnd: HWND) {
        let Some(name) = self.window_of(hwnd) else { return };
        let index = self.window_index(&name).expect("the window");
        if self.windows[index].code_changed() {
            self.submit_tunnel(&name);
        }
    }

    pub fn window_dpi_changed(&mut self, hwnd: HWND, dpi: u32, suggested: &RECT) {
        if let Some(window) = self.windows.iter_mut().find(|window| window.hwnd == hwnd) {
            window.dpi_changed(dpi, suggested);
        }
    }

    // a left click: the login asked, a window open, or else the menu
    pub fn show_pending(&mut self) -> bool {
        if let Some(name) = self.tunnels.iter().find(|tunnel| tunnel.needs_login()).map(|tunnel| tunnel.info.name.clone()) {
            self.show_login(&name, None);
            return true;
        }
        if let Some(window) = self.windows.first() {
            window.activate();
            return true;
        }
        false
    }

    // The user started the app, which was running: what they likely want
    pub fn show_from_user(&mut self) {
        if self.show_pending() {
            return;
        }
        if self.tunnels.is_empty() {
            unsafe { PostMessageW(self.hwnd, WM_APP_IMPORT, 0, 0) };
            return;
        }
        if self.tunnels.len() == 1 && !self.tunnels[0].info.up && !self.tunnels[0].connecting() {
            let name = self.tunnels[0].info.name.clone();
            self.connect(&name);
            return;
        }
        let lines: Vec<String> = self.tunnels.iter().map(|tunnel| format!("{}: {}", tunnel.name(), tunnel.describe())).collect();
        self.notify(&lines.join("\n"), false, None);
    }

    pub fn balloon_clicked(&mut self) {
        if let Some(name) = self.balloon.take() {
            if self.tunnel_index(&name).is_some_and(|index| self.tunnels[index].needs_login()) {
                self.show_login(&name, None);
            }
        }
    }

    // for the removal: the session ends and the window closes; the login page, if logged in
    pub fn release(&mut self, name: &str) -> Option<Page> {
        self.close_window(name);
        let index = self.tunnel_index(name)?;
        let tunnel = &mut self.tunnels[index];
        let page = if tunnel.session == Session::LoggedIn { tunnel.page } else { None };
        tunnel.stopping = tunnel.info.up;
        page
    }

    pub fn removed(&mut self, name: &str) {
        if let Some(index) = self.tunnel_index(name) {
            if let Some(page) = self.tunnels[index].page {
                creds::delete(&page);
            }
            self.tunnels.remove(index);
        }
        settings::set_found_page(name, None);
        self.list_soon();
        self.update_icon();
    }

    // the tunnels to turn off when the app quits, with their login page when logged in
    pub fn active_tunnels(&self) -> Vec<(String, Option<Page>)> {
        self.tunnels
            .iter()
            .filter(|tunnel| tunnel.info.up || tunnel.connecting())
            .map(|tunnel| (tunnel.info.name.clone(), if tunnel.session == Session::LoggedIn { tunnel.page } else { None }))
            .collect()
    }

    // the windows of details, one per tunnel
    pub fn show_details(&mut self, name: &str) {
        if let Some(window) = self.details.iter().find(|window| window.tunnel == name) {
            window.activate();
            return;
        }
        let Some(index) = self.tunnel_index(name) else { return };
        if let Some(window) = DetailsWindow::open(name, details::details(&self.tunnels[index])) {
            self.details.push(window);
        }
    }

    pub fn details_of(&mut self, hwnd: HWND) -> Option<&mut DetailsWindow> {
        self.details.iter_mut().find(|window| window.hwnd == hwnd)
    }

    pub fn close_details(&mut self, hwnd: HWND) {
        self.details.retain(|window| window.hwnd != hwnd);
    }

    // every second; the window of a tunnel removed closes
    fn update_details(&mut self) {
        let tunnels = &self.tunnels;
        self.details.retain_mut(|window| match tunnels.iter().find(|tunnel| tunnel.info.name == window.tunnel) {
            Some(tunnel) => {
                window.update(details::details(tunnel));
                true
            }
            None => false,
        });
    }

    pub fn shutdown(&mut self) {
        self.exiting = true;
        unsafe { KillTimer(self.hwnd, TIMER) };
        self.windows.clear();
        self.details.clear();
        self.remove_icon();
    }

    pub fn build_menu(&self) -> (HMENU, Vec<Command>) {
        let mut commands = Vec::new();
        let mut default = None;
        unsafe {
            let menu = CreatePopupMenu();
            let add = |menu: HMENU, commands: &mut Vec<Command>, text: &str, command: Command| -> u32 {
                commands.push(command);
                let id = commands.len() as u32;
                AppendMenuW(menu, MF_STRING, id as usize, wide(text).as_ptr());
                id
            };
            let label = |menu: HMENU, text: &str| {
                AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, wide(text).as_ptr());
            };
            let separator = |menu: HMENU| {
                AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
            };
            if self.service == ServiceState::Unavailable {
                label(menu, strings::MENU_SERVICE_DOWN);
                add(menu, &mut commands, strings::MENU_START_SERVICE, Command::StartService);
                separator(menu);
            } else if self.tunnels.is_empty() {
                label(menu, strings::MENU_NO_TUNNELS);
                separator(menu);
            }
            for tunnel in &self.tunnels {
                label(menu, &format!("{}: {}", tunnel.name(), tunnel.describe()));
                let name = tunnel.info.name.clone();
                if tunnel.stopping {
                } else if tunnel.info.up || tunnel.connecting() {
                    if tunnel.needs_login() {
                        let id = add(menu, &mut commands, strings::MENU_LOG_IN, Command::LogIn(name.clone()));
                        default.get_or_insert(id);
                    }
                    add(menu, &mut commands, strings::MENU_DISCONNECT, Command::Disconnect(name));
                } else {
                    let id = add(menu, &mut commands, strings::MENU_CONNECT, Command::Connect(name));
                    default.get_or_insert(id);
                }
                add(menu, &mut commands, strings::MENU_DETAILS, Command::Details(tunnel.info.name.clone()));
                separator(menu);
            }
            add(menu, &mut commands, strings::MENU_IMPORT, Command::Import);
            if !self.tunnels.is_empty() {
                let remove = CreatePopupMenu();
                for tunnel in &self.tunnels {
                    add(remove, &mut commands, tunnel.name(), Command::Remove(tunnel.info.name.clone()));
                }
                AppendMenuW(menu, MF_POPUP, remove as usize, wide(strings::MENU_REMOVE).as_ptr());
            }
            let logs = CreatePopupMenu();
            add(logs, &mut commands, strings::MENU_APP_LOG, Command::AppLog);
            add(logs, &mut commands, strings::MENU_SERVICE_LOG, Command::ServiceLog);
            AppendMenuW(menu, MF_POPUP, logs as usize, wide(strings::MENU_LOGS).as_ptr());
            label(menu, &strings::menu_version(VERSION));
            separator(menu);
            add(menu, &mut commands, strings::MENU_QUIT, Command::Quit);
            if let Some(id) = default {
                SetMenuDefaultItem(menu, id, 0);
            }
            (menu, commands)
        }
    }
}

fn set_logged_in(tunnel: &mut Tunnel, user: &str, expires: &str, now: Instant) {
    let end = time::parse_iso(expires).unwrap_or_else(|| unix_now() + POLL_LOGGED_IN.as_secs());
    if tunnel.session != Session::LoggedIn {
        log!("{}: logged in as {} until {}", tunnel.info.name, user, expires);
    }
    tunnel.session = Session::LoggedIn;
    tunnel.user = user.to_string();
    tunnel.expires = end;
    tunnel.logged_out = false;
    // look again at the end of the session, if it comes first
    let left = Duration::from_secs(end.saturating_sub(unix_now()) + 2);
    tunnel.next_check = now + POLL_LOGGED_IN.min(left);
}

fn run_command(hwnd: HWND, command: Command) {
    match command {
        Command::Connect(name) => {
            with_app(|app| app.connect(&name));
        }
        Command::Disconnect(name) => {
            with_app(|app| app.disconnect(&name));
        }
        Command::LogIn(name) => {
            with_app(|app| app.show_login(&name, None));
        }
        Command::Import => flows::import_from_file(ptr::null_mut()),
        Command::Remove(name) => flows::remove(ptr::null_mut(), &name),
        Command::Details(name) => {
            with_app(|app| app.show_details(&name));
        }
        Command::AppLog => {
            if let Some(path) = log::path() {
                super::open_in_notepad(&path);
            }
        }
        Command::ServiceLog => super::open_in_notepad(&crate::service::log_path()),
        Command::StartService => {
            if let Err(error) = setup::start_service() {
                message_box(hwnd, &error, MB_ICONERROR);
            }
            with_app(|app| app.list_soon());
        }
        Command::Quit => flows::quit(true),
    }
}

fn show_menu(hwnd: HWND) {
    let Some((menu, commands)) = with_app(|app| app.build_menu()) else { return };
    let mut point = POINT { x: 0, y: 0 };
    let chosen = unsafe {
        GetCursorPos(&mut point);
        // or the menu doesn't close when the user clicks elsewhere
        SetForegroundWindow(hwnd);
        let chosen = TrackPopupMenuEx(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY, point.x, point.y, hwnd, ptr::null());
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);
        chosen
    };
    if chosen > 0 {
        if let Some(command) = commands.into_iter().nth(chosen as usize - 1) {
            run_command(hwnd, command);
        }
    }
}

fn taskbar_created() -> u32 {
    static MESSAGE: OnceLock<u32> = OnceLock::new();
    *MESSAGE.get_or_init(|| unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) })
}

unsafe extern "system" fn window_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match message {
        WM_APP_EVENT => {
            with_app(|app| app.drain());
        }
        WM_TIMER => {
            with_app(|app| app.tick());
        }
        WM_APP_TRAY => match (lparam & 0xffff) as u32 {
            NIN_SELECT | NIN_KEYSELECT => {
                if !with_app(|app| app.show_pending()).unwrap_or(true) {
                    show_menu(hwnd);
                }
            }
            WM_CONTEXTMENU => show_menu(hwnd),
            NIN_BALLOONUSERCLICK => {
                with_app(|app| app.balloon_clicked());
            }
            _ => {}
        },
        WM_APP_SHOW => {
            with_app(|app| app.show_from_user());
        }
        WM_APP_QUIT => flows::quit(false),
        WM_APP_IMPORT => flows::import_from_file(ptr::null_mut()),
        #[cfg(feature = "testing")]
        super::WM_APP_TEST_DETAILS => {
            with_app(|app| {
                if let Some(name) = app.tunnel_names().get(wparam) {
                    app.show_details(&name.clone());
                }
            });
        }
        WM_ENDSESSION => {
            if wparam != 0 {
                // the Restart Manager closes the app for a setup: as when the user quits it
                if lparam as u32 & ENDSESSION_CLOSEAPP != 0 {
                    flows::quit(false);
                } else {
                    with_app(|app| app.shutdown());
                }
            }
        }
        _ if message == taskbar_created() => {
            with_app(|app| app.add_icon());
        }
        _ => return DefWindowProcW(hwnd, message, wparam, lparam),
    }
    0
}

// Another start of the app, and the end asked by the setup, come through events of the session
fn watch_events(hwnd: HWND) {
    let show = unsafe { CreateEventW(ptr::null(), 0, 0, wide(&names::tray_show_event()).as_ptr()) };
    let quit = unsafe { CreateEventW(ptr::null(), 0, 0, wide(&names::tray_quit_event()).as_ptr()) };
    if show.is_null() || quit.is_null() {
        log!("can't create the events of the app");
        return;
    }
    let handles = [show as usize, quit as usize];
    let hwnd = hwnd as usize;
    thread::spawn(move || loop {
        let list: [HANDLE; 2] = [handles[0] as HANDLE, handles[1] as HANDLE];
        let result = unsafe { WaitForMultipleObjects(2, list.as_ptr(), 0, INFINITE) };
        if result == WAIT_OBJECT_0 {
            unsafe { PostMessageW(hwnd as HWND, WM_APP_SHOW, 0, 0) };
        } else {
            if result == WAIT_OBJECT_0 + 1 {
                unsafe { PostMessageW(hwnd as HWND, WM_APP_QUIT, 0, 0) };
            }
            break;
        }
    });
}

// the app runs in this session
pub fn running() -> bool {
    let mutex = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide(&names::tray_mutex()).as_ptr()) };
    if mutex.is_null() {
        return false;
    }
    unsafe { CloseHandle(mutex) };
    true
}

pub fn signal(event: &str) -> bool {
    unsafe {
        let handle = OpenEventW(EVENT_MODIFY_STATE, 0, wide(event).as_ptr());
        if handle.is_null() {
            return false;
        }
        SetEvent(handle);
        CloseHandle(handle);
    }
    true
}

pub fn run(startup: Startup) -> i32 {
    if !cfg!(feature = "testing") && !setup::is_installed_copy() {
        return flows::start_installed();
    }
    let mutex = unsafe { CreateMutexW(ptr::null(), 0, wide(&names::tray_mutex()).as_ptr()) };
    if mutex.is_null() {
        return 1;
    }
    if last_error() == ERROR_ALREADY_EXISTS {
        // already running in this session: it shows itself
        signal(&names::tray_show_event());
        return 0;
    }
    log::init(setup::user_data_dir().join("client.log"));
    log!("{} {} started", PRODUCT, VERSION);
    unsafe {
        CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED as u32);
        let controls = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES,
        };
        InitCommonControlsEx(&controls);
    }
    let class = wide(CLASS);
    let hwnd = unsafe {
        let mut info: WNDCLASSEXW = zeroed();
        info.cbSize = size_of::<WNDCLASSEXW>() as u32;
        info.lpfnWndProc = Some(window_proc);
        info.hInstance = instance();
        info.lpszClassName = class.as_ptr();
        RegisterClassExW(&info);
        // never shown: it gets the messages of the tray
        CreateWindowExW(
            0,
            class.as_ptr(),
            wide(PRODUCT).as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            instance(),
            ptr::null(),
        )
    };
    if hwnd.is_null() {
        return 1;
    }
    taskbar_created();
    APP.with(|cell| *cell.borrow_mut() = Some(App::new(hwnd, startup)));
    with_app(|app| app.start());
    watch_events(hwnd);
    message_loop();
    APP.with(|cell| cell.borrow_mut().take());
    log!("{} quit", PRODUCT);
    unsafe { CloseHandle(mutex) };
    0
}
