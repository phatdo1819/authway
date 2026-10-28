// What the app knows of the tunnels, the same on every system: it asks the service for them, turns them on and
// off, and logs in to the servers that require it, then watches the session. The system shows it through a Shell:
// the icon, the notices, the login windows and the windows of details. The App lives on the thread of the windows;
// the requests run on other threads, and their answers come back as events that the Shell's waker asks to drain.

pub mod details;
pub mod import;

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::api::{self, ApiResult, Page};
use crate::conf::IpNet;
use crate::creds::{self, SavedLogin};
use crate::ipc::{self, CallError, Request, Response, TunnelInfo};
use crate::log;
use crate::names::{PRODUCT, VERSION};
use crate::settings;
use crate::strings;
use crate::time::{self, unix_now};
use details::Details;

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
pub const OTP_LENGTH: usize = 6;

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
    NoOtp,
    // device binding: no device enrolled, and none can enroll
    NotEnrolled,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Startup {
    // started by the user
    Normal,
    // at the sign-in, and after the setup
    SignIn,
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
    // device binding: the next login enrolls this computer
    pub enrolling: bool,
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
    // the notice "connected" was shown in this connection
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
    pub fn new(name: &str) -> Tunnel {
        let now = Instant::now();
        Tunnel {
            info: TunnelInfo { name: name.to_string(), ..TunnelInfo::default() },
            page: None,
            session: Session::Off,
            server_name: String::new(),
            otp_required: true,
            otp_known: false,
            enrolling: false,
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
            changed_at: now.checked_sub(Duration::from_secs(3600)).unwrap_or(now),
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

    // the one of the configuration, or the one found on an earlier connection: only in the routes of the tunnel, so
    // the password goes only through it. A found one that isn't anymore, after a new configuration, is forgotten.
    fn set_page(&mut self) {
        let routes = nets(&self.info.routes);
        let routed = |page: &Page| api::routed(&routes, page.host);
        self.page = match self.info.login.as_deref().and_then(Page::parse) {
            Some(page) => Some(page).filter(routed),
            None => {
                let found = settings::found_page(&self.info.name);
                if let Some(page) = found.filter(|page| !routed(page)) {
                    log!("{}: the login page {} isn't in the routes of the VPN anymore", self.info.name, page);
                    settings::set_found_page(&self.info.name, None);
                }
                found.filter(routed)
            }
        };
    }

    // the login page while logged in, and the network interface to reach it: for the logout
    fn session_page(&self) -> Option<(Page, u32)> {
        self.page.filter(|_| self.session == Session::LoggedIn).map(|page| (page, self.info.interface))
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

    pub fn connecting(&self) -> bool {
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
            Session::NoOtp => strings::STATE_NO_OTP.to_string(),
            Session::NotEnrolled => strings::STATE_NOT_ENROLLED.to_string(),
        }
    }

    // what the icon shows first, higher first
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
            Session::Blocked | Session::NoUser | Session::NoOtp | Session::NotEnrolled => Icon::Refused,
            Session::LoggedIn | Session::NotRequired => Icon::Connected,
            _ => Icon::Attention,
        }
    }
}

// the states of the icon, in the order of importance
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Icon {
    Idle = 0,
    Connected = 1,
    Attention = 2,
    Refused = 3,
}

// The refusals of the login page that the user can't solve: the administrator has to act
fn refusal(error: &str) -> Option<(Session, &'static str)> {
    match error {
        "blocked" => Some((Session::Blocked, strings::ERROR_BLOCKED)),
        "no_user" => Some((Session::NoUser, strings::ERROR_NO_USER)),
        "no_otp" => Some((Session::NoOtp, strings::ERROR_NO_OTP)),
        "device_not_enrolled" => Some((Session::NotEnrolled, strings::ERROR_NOT_ENROLLED)),
        _ => None,
    }
}

fn refusal_text(session: Session) -> Option<&'static str> {
    match session {
        Session::Blocked => Some(strings::ERROR_BLOCKED),
        Session::NoUser => Some(strings::ERROR_NO_USER),
        Session::NoOtp => Some(strings::ERROR_NO_OTP),
        Session::NotEnrolled => Some(strings::ERROR_NOT_ENROLLED),
        _ => None,
    }
}

// What a status says of device binding: whether no device can log in, and whether the next login enrolls this one
fn device_state(result: &ApiResult) -> (bool, bool) {
    let Some(device) = result.data.get("device").and_then(serde_json::Value::as_object) else {
        return (false, false);
    };
    let flag = |key: &str| device.get(key).and_then(serde_json::Value::as_bool).unwrap_or(false);
    let open = flag("required") && !flag("enrolled");
    (open && !flag("enrollment_open"), open && flag("enrollment_open"))
}

// A login, with the proof of this device when the server requires it: the challenge of a new status, signed by the
// service. Once more with a new challenge if it expired meanwhile.
fn log_in(tunnel: &str, page: &Page, interface: u32, username: &str, password: &str, code: &str) -> ApiResult {
    let mut result = ApiResult::default();
    for _ in 0..2 {
        let status = api::status(page, interface);
        let Some((challenge, machine_id)) = api::device_challenge(&status) else {
            return api::login(page, interface, username, password, code, None);
        };
        let request = Request::Sign {
            name: tunnel.to_string(),
            host: page.host,
            challenge,
            username: username.to_string(),
            machine_id,
        };
        let proof = match ipc::call(&request) {
            Ok(response) if response.ok && response.device.is_some() => response.device,
            Ok(response) => return ApiResult::local(response.message(), strings::ERROR_DEVICE_REQUIRED),
            Err(error) => return ApiResult::local(&call_message(&error), &call_message(&error)),
        };
        result = api::login(page, interface, username, password, code, proof.as_ref());
        if !(result.status == 401 && result.error() == "challenge_expired") {
            break;
        }
    }
    result
}

pub enum Event {
    List { requested: Instant, result: Result<Response, CallError> },
    Up { name: String, result: Result<Response, CallError> },
    Down { name: String, result: Result<Response, CallError> },
    Status { name: String, generation: u32, result: ApiResult },
    Login { name: String, generation: u32, result: ApiResult, username: String, password: String, remember: bool },
    Found { name: String, generation: u32, page: Option<Page> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

// The menu of the icon, as each system draws it
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MenuItem {
    // greyed
    Label(String),
    // the default one is the first that turns on or logs in
    Action { text: String, command: Command, default: bool },
    Submenu { text: String, items: Vec<MenuItem> },
    Separator,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum ServiceState {
    Unknown,
    Running,
    Unavailable,
    Failed,
}

pub struct LoginValues {
    pub username: String,
    pub password: String,
    pub code: String,
    pub remember: bool,
}

// What a login window opens with
pub struct LoginForm<'a> {
    pub tunnel: &'a str,
    pub heading: &'a str,
    pub hint: &'a str,
    pub saved: &'a SavedLogin,
    pub can_remember: bool,
    pub otp_required: bool,
    pub notice: Option<&'a str>,
}

// The login window of a tunnel: it closes when dropped. Cancel, or closing it, disconnects.
pub trait LoginView {
    fn set_heading(&mut self, text: &str);
    fn set_hint(&mut self, text: &str);
    fn set_notice(&mut self, text: Option<&str>);
    fn set_error(&mut self, text: Option<&str>);
    fn set_otp_required(&mut self, required: bool);
    fn set_busy(&mut self, busy: bool);
    fn values(&self) -> LoginValues;
    // after a refused login: a code is good once
    fn clear_code(&self);
    // Only the digits of a pasted code stay; true when the sixth one makes the login complete
    fn code_changed(&self) -> bool;
    fn activate(&self);
    // the window, as the events of the system name it
    fn id(&self) -> usize;
}

// The window of details of a tunnel: it closes when dropped
pub trait DetailsView {
    fn update(&mut self, details: Details);
    fn activate(&self);
    fn id(&self) -> usize;
}

// Asks the thread of the windows to drain the events, from any thread
pub type Waker = Arc<dyn Fn() + Send + Sync>;

pub trait Shell {
    type Login: LoginView;
    type Details: DetailsView;
    fn waker(&self) -> Waker;
    // the icon, and the text next to it
    fn show(&mut self, icon: Icon, tip: &str);
    fn notify(&mut self, text: &str, warning: bool);
    fn open_login(&mut self, form: LoginForm) -> Option<Self::Login>;
    fn open_details(&mut self, tunnel: &str, details: Details) -> Option<Self::Details>;
    // the user wants to add a VPN: the file dialog, out of the App
    fn import_later(&mut self);
}

struct LoginWindow<V> {
    tunnel: String,
    // Connect was pressed before the login page answered: the login goes as soon as it does
    pending_submit: bool,
    view: V,
}

struct DetailsWindow<V> {
    tunnel: String,
    view: V,
}

pub struct App<S: Shell> {
    pub shell: S,
    sender: Sender<Event>,
    receiver: Receiver<Event>,
    waker: Waker,
    tunnels: Vec<Tunnel>,
    can_manage: bool,
    service: ServiceState,
    listing: bool,
    next_list: Instant,
    windows: Vec<LoginWindow<S::Login>>,
    details: Vec<DetailsWindow<S::Details>>,
    shown: Option<(Icon, String)>,
    balloon: Option<String>,
    exiting: bool,
    pending_connect: Option<String>,
    startup: Option<Startup>,
}

pub fn error_message(result: &ApiResult) -> String {
    if let Some(text) = &result.local_error {
        return text.clone();
    }
    if !result.reached() {
        return strings::ERROR_UNREACHABLE.to_string();
    }
    match (result.status, result.error()) {
        (401, "device_mismatch") => strings::ERROR_DEVICE_MISMATCH.to_string(),
        (401, "challenge_expired") => strings::ERROR_FAILED.to_string(),
        (403, "device_required") => strings::ERROR_DEVICE_REQUIRED.to_string(),
        _ => match_status(result),
    }
}

fn match_status(result: &ApiResult) -> String {
    match result.status {
        401 => strings::ERROR_CREDENTIALS.to_string(),
        // nginx answers too many requests without retry_after
        429 => strings::error_attempts(((result.get_int("retry_after", 60) + 59) / 60).max(1)),
        403 => refusal(result.error()).map_or(strings::ERROR_FORBIDDEN, |(_, text)| text).to_string(),
        _ => strings::ERROR_FAILED.to_string(),
    }
}

pub fn call_message(error: &CallError) -> String {
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

fn nets(texts: &[String]) -> Vec<IpNet> {
    texts.iter().filter_map(|text| IpNet::parse(text)).collect()
}

impl<S: Shell> App<S> {
    pub fn new(shell: S, startup: Startup) -> App<S> {
        let (sender, receiver) = mpsc::channel();
        let waker = shell.waker();
        App {
            shell,
            sender,
            receiver,
            waker,
            tunnels: Vec::new(),
            can_manage: false,
            service: ServiceState::Unknown,
            listing: false,
            next_list: Instant::now(),
            windows: Vec::new(),
            details: Vec::new(),
            shown: None,
            balloon: None,
            exiting: false,
            pending_connect: None,
            startup: Some(startup),
        }
    }

    pub fn start(&mut self) {
        self.update_icon();
        self.list();
    }

    fn spawn(&self, work: impl FnOnce() -> Event + Send + 'static) {
        // the tests never reach the service, the installed one, nor the network
        if cfg!(test) {
            return;
        }
        let sender = self.sender.clone();
        let waker = self.waker.clone();
        thread::spawn(move || {
            let event = work();
            if sender.send(event).is_ok() {
                waker();
            }
        });
    }

    fn tunnel_index(&self, name: &str) -> Option<usize> {
        self.tunnels.iter().position(|tunnel| tunnel.info.name == name)
    }

    fn window_index(&self, name: &str) -> Option<usize> {
        self.windows.iter().position(|window| window.tunnel == name)
    }

    fn window_of(&self, id: usize) -> Option<String> {
        self.windows.iter().find(|window| window.view.id() == id).map(|window| window.tunnel.clone())
    }

    pub fn tunnel_names(&self) -> Vec<String> {
        self.tunnels.iter().map(|tunnel| tunnel.info.name.clone()).collect()
    }

    pub fn tunnels(&self) -> &[Tunnel] {
        &self.tunnels
    }

    pub fn service_state(&self) -> ServiceState {
        self.service
    }

    pub fn can_manage(&self) -> bool {
        self.can_manage
    }

    // the icon

    pub fn summary(&self) -> (Icon, String) {
        if self.service == ServiceState::Unavailable {
            return (Icon::Idle, format!("{}: {}", PRODUCT, strings::MENU_SERVICE_DOWN));
        }
        match self.tunnels.iter().max_by_key(|tunnel| tunnel.rank()) {
            Some(tunnel) if tunnel.rank() != Icon::Idle => (tunnel.rank(), format!("{}: {}", tunnel.name(), tunnel.describe())),
            _ => (Icon::Idle, format!("{}: {}", PRODUCT, strings::STATE_OFF)),
        }
    }

    pub fn update_icon(&mut self) {
        let summary = self.summary();
        if self.shown.as_ref() == Some(&summary) {
            return;
        }
        self.shell.show(summary.0, &summary.1);
        self.shown = Some(summary);
    }

    // once more, when the system lost the icon
    pub fn refresh_icon(&mut self) {
        self.shown = None;
        self.update_icon();
    }

    fn notify(&mut self, text: &str, warning: bool, tunnel: Option<&str>) {
        self.shell.notify(text, warning);
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
        if !self.exiting {
            self.update_icon();
        }
    }

    fn list(&mut self) {
        self.listing = true;
        let requested = Instant::now();
        self.spawn(move || Event::List { requested, result: ipc::call(&Request::List) });
    }

    pub fn list_soon(&mut self) {
        self.next_list = Instant::now();
    }

    // every second
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
            // the login page only through the network interface of the tunnel: once the service has listed it
            let interface = tunnel.info.interface;
            match tunnel.page {
                Some(page) => {
                    if !tunnel.busy && now >= tunnel.next_check && interface != 0 {
                        tunnel.busy = true;
                        checks.push((tunnel.info.name.clone(), tunnel.generation, page, interface));
                    }
                }
                None => {
                    if !tunnel.searched && tunnel.info.handshake > 0 && interface != 0 {
                        tunnel.searched = true;
                        let routes = nets(&tunnel.info.routes);
                        let candidates = api::candidates_of(&nets(&tunnel.info.addresses), &routes);
                        if !candidates.is_empty() {
                            searches.push((tunnel.info.name.clone(), tunnel.generation, candidates, routes, interface));
                        }
                    }
                    if !tunnel.announced && tunnel.info.handshake > 0 {
                        tunnel.announced = true;
                        announce.push(tunnel.title());
                    }
                }
            }
        }
        for (name, generation, page, interface) in checks {
            self.spawn(move || Event::Status { name, generation, result: api::status(&page, interface) });
        }
        for (name, generation, candidates, routes, interface) in searches {
            log!("{}: looking for the login page at {:?}", name, candidates);
            self.spawn(move || Event::Found {
                name,
                generation,
                page: api::discover(&candidates, &routes, interface, api::DEFAULT_PORT, api::WEB_PORT),
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
            // a new configuration: another login page, or other routes for the one found
            let page_changed =
                position.is_none() || tunnel.info.login != info.login || tunnel.info.routes != info.routes;
            let (up, since) = (tunnel.info.up, tunnel.info.since);
            tunnel.info = info;
            // a list asked before the last turn on or off here doesn't know of it
            if requested < tunnel.changed_at {
                tunnel.info.up = up;
                tunnel.info.since = since;
            }
            if page_changed {
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
                        window.view.set_busy(false);
                        window.view.set_error(Some(&strings::error_connect(&message)));
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
                let (not_enrolled, enrolling) = device_state(&result);
                tunnel.enrolling = enrolling;
                let refused = ["blocked", "no_user", "no_otp"]
                    .into_iter()
                    .find(|key| result.get_bool(key))
                    .or(not_enrolled.then_some("device_not_enrolled"));
                if result.get_bool("authenticated") {
                    set_logged_in(tunnel, result.get_str("user"), result.get_str("expires"), now);
                    close_window = true;
                    if !tunnel.announced {
                        tunnel.announced = true;
                        let until = time::format_local(tunnel.expires);
                        balloon = Some((strings::notice_logged_in(&tunnel.title(), &tunnel.user, &until), false));
                    }
                } else if let Some((state, text)) = refused.and_then(refusal) {
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
                    window.view.set_heading(&tunnel.title());
                    window.view.set_otp_required(tunnel.otp_required);
                    window.view.set_hint(if tunnel.otp_required { strings::LOGIN_HINT_OTP } else { strings::LOGIN_HINT });
                    if tunnel.enrolling {
                        window.view.set_notice(Some(strings::NOTICE_ENROLL));
                    }
                    if window.pending_submit {
                        submit = true;
                    } else {
                        window.view.set_error(None);
                    }
                }
                Session::Unreachable if tunnel.no_answer() => window.view.set_error(Some(strings::ERROR_NO_ANSWER)),
                session => {
                    if let Some(text) = refusal_text(session) {
                        window.view.set_error(Some(text));
                    }
                }
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
        let session_page = tunnel.session_page();
        let name = name.to_string();
        log!("{}: disconnecting", name);
        self.spawn(move || {
            if let Some((page, interface)) = session_page {
                let result = api::logout(&page, interface, Some(LOGOUT_TIMEOUT));
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
                window.view.set_notice(notice);
            }
            window.view.activate();
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
        let refused = refusal_text(tunnel.session);
        let title = tunnel.title();
        let form = LoginForm {
            tunnel: name,
            heading: &title,
            hint: &hint,
            saved: &saved,
            can_remember: settings::can_remember_password(),
            otp_required: tunnel.otp_required,
            notice: notice.or(tunnel.enrolling.then_some(strings::NOTICE_ENROLL)),
        };
        if let Some(mut view) = self.shell.open_login(form) {
            view.set_error(refused);
            self.windows.push(LoginWindow { tunnel: name.to_string(), pending_submit: false, view });
        }
    }

    fn close_window(&mut self, name: &str) {
        if let Some(index) = self.window_index(name) {
            // the window goes when dropped
            self.windows.remove(index);
        }
    }

    // the login window, for what only its system does with it
    pub fn login_of(&mut self, id: usize) -> Option<&mut S::Login> {
        self.windows.iter_mut().find(|window| window.view.id() == id).map(|window| &mut window.view)
    }

    pub fn submit(&mut self, id: usize) {
        if let Some(name) = self.window_of(id) {
            self.submit_tunnel(&name);
        }
    }

    fn submit_tunnel(&mut self, name: &str) {
        let (Some(window), Some(index)) = (self.window_index(name), self.tunnel_index(name)) else { return };
        let values = self.windows[window].view.values();
        let tunnel = &self.tunnels[index];
        let ready = tunnel.needs_login();
        let missing_otp = tunnel.otp_required && values.code.len() != OTP_LENGTH && (ready || tunnel.otp_known);
        let restart = !tunnel.info.up && !tunnel.connecting() && !tunnel.stopping;
        let window_ref = &mut self.windows[window];
        if values.username.is_empty() || values.password.is_empty() || missing_otp {
            window_ref.pending_submit = false;
            window_ref.view.set_busy(false);
            let text = if missing_otp && !values.username.is_empty() && !values.password.is_empty() {
                strings::ERROR_MISSING_OTP
            } else {
                strings::ERROR_MISSING
            };
            window_ref.view.set_error(Some(text));
            return;
        }
        window_ref.view.set_error(None);
        if !ready {
            // still connecting: the login goes as soon as the login page answers
            window_ref.pending_submit = true;
            window_ref.view.set_busy(true);
            if restart {
                self.start_up(index);
            }
            return;
        }
        let Some(page) = tunnel.page else { return };
        window_ref.pending_submit = false;
        window_ref.view.set_busy(true);
        let (generation, interface) = (tunnel.generation, tunnel.info.interface);
        let code = if tunnel.otp_required { values.code } else { String::new() };
        let name = name.to_string();
        let (username, password, remember) = (values.username, values.password, values.remember);
        self.spawn(move || {
            let result = log_in(&name, &page, interface, &username, &password, &code);
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
                    log!("{}: can't save the username in {}", name, creds::STORE_NAME);
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
            window.view.set_busy(false);
            window.view.set_error(Some(&error_message(&result)));
            window.view.clear_code();
        }
        if result.status == 403 {
            if let Some((state, _)) = refusal(result.error()) {
                let tunnel = &mut self.tunnels[index];
                tunnel.session = state;
                tunnel.next_check = now + POLL_REFUSED;
            }
        }
    }

    // the window is the connection: closing it disconnects
    pub fn cancel(&mut self, id: usize) {
        let Some(name) = self.window_of(id) else { return };
        self.close_window(&name);
        if let Some(index) = self.tunnel_index(&name) {
            let tunnel = &self.tunnels[index];
            if tunnel.info.up || tunnel.connecting() {
                self.disconnect(&name);
            }
        }
    }

    pub fn code_changed(&mut self, id: usize) {
        let Some(name) = self.window_of(id) else { return };
        let index = self.window_index(&name).expect("the window");
        if self.windows[index].view.code_changed() {
            self.submit_tunnel(&name);
        }
    }

    // a click on the icon: the login asked, a window open; false when there's none
    pub fn show_pending(&mut self) -> bool {
        if let Some(name) = self.tunnels.iter().find(|tunnel| tunnel.needs_login()).map(|tunnel| tunnel.info.name.clone()) {
            self.show_login(&name, None);
            return true;
        }
        if let Some(window) = self.windows.first() {
            window.view.activate();
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
            self.shell.import_later();
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

    // a click on the last notice
    pub fn balloon_clicked(&mut self) {
        if let Some(name) = self.balloon.take() {
            if self.tunnel_index(&name).is_some_and(|index| self.tunnels[index].needs_login()) {
                self.show_login(&name, None);
            }
        }
    }

    // for the removal: the session ends and the window closes; the login page and its interface, if logged in
    pub fn release(&mut self, name: &str) -> Option<(Page, u32)> {
        self.close_window(name);
        let index = self.tunnel_index(name)?;
        let tunnel = &mut self.tunnels[index];
        tunnel.stopping = tunnel.info.up;
        tunnel.session_page()
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

    // the tunnels to turn off when the app quits, with their login page and its interface when logged in
    pub fn active_tunnels(&self) -> Vec<(String, Option<(Page, u32)>)> {
        self.tunnels
            .iter()
            .filter(|tunnel| tunnel.info.up || tunnel.connecting())
            .map(|tunnel| (tunnel.info.name.clone(), tunnel.session_page()))
            .collect()
    }

    // the windows of details, one per tunnel
    pub fn show_details(&mut self, name: &str) {
        if let Some(window) = self.details.iter().find(|window| window.tunnel == name) {
            window.view.activate();
            return;
        }
        let Some(index) = self.tunnel_index(name) else { return };
        let rows = details::details(&self.tunnels[index]);
        if let Some(view) = self.shell.open_details(name, rows) {
            self.details.push(DetailsWindow { tunnel: name.to_string(), view });
        }
    }

    pub fn details_of(&mut self, id: usize) -> Option<&mut S::Details> {
        self.details.iter_mut().find(|window| window.view.id() == id).map(|window| &mut window.view)
    }

    pub fn close_details(&mut self, id: usize) {
        self.details.retain(|window| window.view.id() != id);
    }

    // every second; the window of a tunnel removed closes
    fn update_details(&mut self) {
        let tunnels = &self.tunnels;
        self.details.retain_mut(|window| match tunnels.iter().find(|tunnel| tunnel.info.name == window.tunnel) {
            Some(tunnel) => {
                window.view.update(details::details(tunnel));
                true
            }
            None => false,
        });
    }

    // the windows close; the system takes the icon away
    pub fn shutdown(&mut self) {
        self.exiting = true;
        self.windows.clear();
        self.details.clear();
    }

    pub fn menu(&self) -> Vec<MenuItem> {
        let mut items = Vec::new();
        let mut has_default = false;
        let mut action = |text: &str, command: Command, wanted: bool| {
            let default = wanted && !has_default;
            has_default |= default;
            MenuItem::Action { text: text.to_string(), command, default }
        };
        if self.service == ServiceState::Unavailable {
            items.push(MenuItem::Label(strings::MENU_SERVICE_DOWN.to_string()));
            items.push(action(strings::MENU_START_SERVICE, Command::StartService, false));
            items.push(MenuItem::Separator);
        } else if self.tunnels.is_empty() {
            items.push(MenuItem::Label(strings::MENU_NO_TUNNELS.to_string()));
            items.push(MenuItem::Separator);
        }
        for tunnel in &self.tunnels {
            items.push(MenuItem::Label(format!("{}: {}", tunnel.name(), tunnel.describe())));
            let name = tunnel.info.name.clone();
            if tunnel.stopping {
            } else if tunnel.info.up || tunnel.connecting() {
                if tunnel.needs_login() {
                    items.push(action(strings::MENU_LOG_IN, Command::LogIn(name.clone()), true));
                }
                items.push(action(strings::MENU_DISCONNECT, Command::Disconnect(name), false));
            } else {
                items.push(action(strings::MENU_CONNECT, Command::Connect(name), true));
            }
            items.push(action(strings::MENU_DETAILS, Command::Details(tunnel.info.name.clone()), false));
            items.push(MenuItem::Separator);
        }
        items.push(action(strings::MENU_IMPORT, Command::Import, false));
        if !self.tunnels.is_empty() {
            let remove = self
                .tunnels
                .iter()
                .map(|tunnel| action(tunnel.name(), Command::Remove(tunnel.info.name.clone()), false))
                .collect();
            items.push(MenuItem::Submenu { text: strings::MENU_REMOVE.to_string(), items: remove });
        }
        let logs = vec![
            action(strings::MENU_APP_LOG, Command::AppLog, false),
            action(strings::MENU_SERVICE_LOG, Command::ServiceLog, false),
        ];
        items.push(MenuItem::Submenu { text: strings::MENU_LOGS.to_string(), items: logs });
        items.push(MenuItem::Label(strings::menu_version(VERSION)));
        items.push(MenuItem::Separator);
        items.push(action(strings::MENU_QUIT, Command::Quit, false));
        items
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    // what the windows were asked, in order
    type Journal = Rc<RefCell<Vec<String>>>;

    struct FakeLogin {
        id: usize,
        values: (String, String, String),
        journal: Journal,
    }

    impl LoginView for FakeLogin {
        fn set_heading(&mut self, text: &str) {
            self.journal.borrow_mut().push(format!("heading {}", text));
        }
        fn set_hint(&mut self, _text: &str) {}
        fn set_notice(&mut self, text: Option<&str>) {
            self.journal.borrow_mut().push(format!("notice {:?}", text));
        }
        fn set_error(&mut self, text: Option<&str>) {
            self.journal.borrow_mut().push(format!("error {:?}", text));
        }
        fn set_otp_required(&mut self, required: bool) {
            self.journal.borrow_mut().push(format!("otp {}", required));
        }
        fn set_busy(&mut self, busy: bool) {
            self.journal.borrow_mut().push(format!("busy {}", busy));
        }
        fn values(&self) -> LoginValues {
            let (username, password, code) = self.values.clone();
            LoginValues { username, password, code, remember: false }
        }
        fn clear_code(&self) {}
        fn code_changed(&self) -> bool {
            false
        }
        fn activate(&self) {
            self.journal.borrow_mut().push("activate".into());
        }
        fn id(&self) -> usize {
            self.id
        }
    }

    struct FakeDetails(usize);

    impl DetailsView for FakeDetails {
        fn update(&mut self, _details: Details) {}
        fn activate(&self) {}
        fn id(&self) -> usize {
            self.0
        }
    }

    struct FakeShell {
        journal: Journal,
        next_id: usize,
    }

    impl Shell for FakeShell {
        type Login = FakeLogin;
        type Details = FakeDetails;
        fn waker(&self) -> Waker {
            Arc::new(|| {})
        }
        fn show(&mut self, icon: Icon, tip: &str) {
            self.journal.borrow_mut().push(format!("icon {:?} {}", icon, tip));
        }
        fn notify(&mut self, text: &str, warning: bool) {
            self.journal.borrow_mut().push(format!("notify {} {}", warning, text));
        }
        fn open_login(&mut self, form: LoginForm) -> Option<FakeLogin> {
            self.next_id += 1;
            self.journal.borrow_mut().push(format!("login {} {:?}", form.tunnel, form.notice));
            let values = ("alice".to_string(), "Secret,1234".to_string(), String::new());
            Some(FakeLogin { id: self.next_id, values, journal: self.journal.clone() })
        }
        fn open_details(&mut self, _tunnel: &str, _details: Details) -> Option<FakeDetails> {
            self.next_id += 1;
            Some(FakeDetails(self.next_id))
        }
        fn import_later(&mut self) {
            self.journal.borrow_mut().push("import".into());
        }
    }

    fn app() -> (App<FakeShell>, Journal) {
        let journal = Journal::default();
        let shell = FakeShell { journal: journal.clone(), next_id: 0 };
        (App::new(shell, Startup::SignIn), journal)
    }

    // Office, on, with its login page, as a list of the service leaves it
    fn office_on(app: &mut App<FakeShell>) {
        let info = TunnelInfo {
            name: "Office".into(),
            up: true,
            login: Some("http://10.103.1.1:8181/".into()),
            routes: vec!["10.103.1.0/24".into()],
            interface: 7,
            since: unix_now(),
            ..TunnelInfo::default()
        };
        let response = Response { ok: true, tunnels: vec![info], can_manage: true, ..Response::default() };
        app.on_list(Instant::now(), Ok(response));
    }

    fn status(json: &str) -> ApiResult {
        let data = match serde_json::from_str::<serde_json::Value>(json).unwrap() {
            serde_json::Value::Object(data) => data,
            _ => unreachable!(),
        };
        ApiResult { status: 200, data, ..ApiResult::default() }
    }

    #[test]
    fn the_login_asked_then_refused() {
        let (mut app, journal) = app();
        office_on(&mut app);
        let generation = app.tunnels[0].generation;
        assert_eq!(app.tunnels[0].session, Session::Checking);
        // not logged in: the window opens by itself, once
        app.on_status("Office", generation, status(r#"{"authenticated":false,"otp_required":true,"server":"HQ"}"#));
        assert_eq!(app.tunnels[0].session, Session::NeedLogin);
        assert!(journal.borrow().contains(&"login Office None".to_string()));
        assert_eq!(app.menu()[1], MenuItem::Action { text: strings::MENU_LOG_IN.into(), command: Command::LogIn("Office".into()), default: true });
        // the firewall refuses the user: no OTP secret, the window says why and stays
        app.tunnels[0].busy = true;
        app.on_status("Office", generation, status(r#"{"authenticated":false,"otp_required":true,"no_otp":true}"#));
        assert_eq!(app.tunnels[0].session, Session::NoOtp);
        assert!(journal.borrow().contains(&format!("error {:?}", Some(strings::ERROR_NO_OTP))));
        assert_eq!(app.summary().0, Icon::Refused);
        assert_eq!(app.tunnels[0].describe(), strings::STATE_NO_OTP);
        // an answer of an earlier connection is dropped
        app.on_status("Office", generation - 1, status(r#"{"authenticated":true,"user":"alice"}"#));
        assert_eq!(app.tunnels[0].session, Session::NoOtp);
    }

    #[test]
    fn logged_in_then_ended_by_the_firewall() {
        let (mut app, journal) = app();
        office_on(&mut app);
        let generation = app.tunnels[0].generation;
        app.on_status(
            "Office",
            generation,
            status(r#"{"authenticated":true,"otp_required":false,"user":"alice","expires":"2099-01-01T00:00:00+00:00"}"#),
        );
        assert_eq!((app.tunnels[0].session, app.tunnels[0].user.as_str()), (Session::LoggedIn, "alice"));
        assert_eq!(app.summary().0, Icon::Connected);
        assert_eq!(app.active_tunnels()[0].1, Some((Page::parse("http://10.103.1.1:8181/").unwrap(), 7)));
        // the session ended on the firewall: the window comes back with a notice
        app.on_status("Office", generation, status(r#"{"authenticated":false,"otp_required":false}"#));
        assert_eq!(app.tunnels[0].session, Session::NeedLogin);
        assert!(journal.borrow().contains(&format!("login Office {:?}", Some(strings::NOTICE_SESSION_ENDED))));
        // the window is the connection: closing it disconnects
        let id = app.windows[0].view.id();
        app.cancel(id);
        assert!(app.windows.is_empty());
        assert!(app.tunnels[0].stopping);
        assert_eq!(app.tunnels[0].describe(), strings::STATE_DISCONNECTING);
    }

    #[test]
    fn refusals_of_the_login() {
        let failure = |status: u16, json: &str| {
            let mut result = super::tests::status(json);
            result.status = status;
            error_message(&result)
        };
        assert_eq!(failure(401, r#"{"error":"invalid_credentials"}"#), strings::ERROR_CREDENTIALS);
        assert_eq!(failure(403, r#"{"error":"no_otp"}"#), strings::ERROR_NO_OTP);
        assert_eq!(failure(403, r#"{"error":"blocked"}"#), strings::ERROR_BLOCKED);
        assert_eq!(failure(403, r#"{"error":"forbidden"}"#), strings::ERROR_FORBIDDEN);
        assert_eq!(failure(429, r#"{"retry_after":61}"#), strings::error_attempts(2));
        assert_eq!(error_message(&ApiResult::default()), strings::ERROR_UNREACHABLE);
    }

    #[test]
    fn the_menu() {
        let (mut app, _) = app();
        let response = Response { ok: true, ..Response::default() };
        app.on_list(Instant::now(), Ok(response));
        let menu = app.menu();
        assert_eq!(menu[0], MenuItem::Label(strings::MENU_NO_TUNNELS.into()));
        assert!(!menu.iter().any(|item| matches!(item, MenuItem::Submenu { text, .. } if text == strings::MENU_REMOVE)));
        app.on_list(Instant::now(), Err(CallError::Unavailable));
        assert_eq!(app.menu()[1], MenuItem::Action { text: strings::MENU_START_SERVICE.into(), command: Command::StartService, default: false });
        assert_eq!(app.summary().0, Icon::Idle);
    }
}
