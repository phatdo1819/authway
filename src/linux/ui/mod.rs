// The app in the tray and its main window on Linux, with GTK 3: the state lives in one App (client/) on the main
// thread, reached through with_app(). The modal steps (the questions, the file chooser, the password of an
// administrator) run outside of it, in flows.rs, so that the events that they let through find the App free; the
// same as on Windows and macOS.
//
// What each widget does is in TARGETS, by the address of the widget: the signals of GTK call the few functions
// below, which find it there and run it once the signal is done, with later().

pub mod details;
pub mod flows;
pub mod gtk;
pub mod home;
pub mod login;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use crate::client::details::Details;
use crate::client::{self, Command, Icon, LoginForm, MenuItem, Shell, Waker};
use crate::log;
use crate::names::{PRODUCT, VERSION};
use crate::settings;
use crate::setup;
use crate::strings;
use gtk::{c, g, Widget};

pub use crate::client::Startup;

pub type App = client::App<LinuxShell>;

// What a widget does when the user uses it
#[derive(Clone)]
pub enum Target {
    // an item of the menu of the tray
    Command(Command),
    // a control of the main window
    Home(home::Action),
    LoginConnect,
    LoginCancel,
    LoginCode,
    DetailsCopy,
    DetailsClose,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    static TARGETS: RefCell<HashMap<usize, Target>> = RefCell::new(HashMap::new());
    // the app sets a switch: not the user
    static UPDATING: Cell<bool> = const { Cell::new(false) };
    // the app quits: the tunnels are already off
    static QUITTING: Cell<bool> = const { Cell::new(false) };
    // the menu of the tray as it is, to make it again only when it changes
    static TRAY_MENU: RefCell<Option<Vec<MenuItem>>> = const { RefCell::new(None) };
    // the last notice, kept for a click on it
    static NOTICE: Cell<*mut c_void> = const { Cell::new(std::ptr::null_mut()) };
}

// The App, if it's free: None while a call on it is running, for the events that it causes itself
pub fn with_app<R>(action: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.with(|cell| {
        let mut guard = cell.try_borrow_mut().ok()?;
        let app = guard.as_mut()?;
        Some(action(app))
    })
}

type Work = Box<dyn FnOnce() + Send>;

unsafe extern "C" fn run_later(data: *mut c_void) -> c_int {
    let work = unsafe { Box::from_raw(data as *mut Work) };
    work();
    0
}

// on the main thread, once the current event is done: out of the calls on the App. From any thread.
pub fn later(work: impl FnOnce() + Send + 'static) {
    let work: Box<Work> = Box::new(Box::new(work));
    gtk::idle(run_later, Box::into_raw(work) as *mut c_void);
}

// the id of a window, as the App knows it
pub fn window_id(window: Widget) -> usize {
    window as usize
}

// the app sets a switch: its signal isn't the user's
pub fn set_switch(switch: Widget, on: bool) {
    UPDATING.set(true);
    gtk::set_switch(switch, on);
    UPDATING.set(false);
}

// The signals of GTK, each with the signature of its signal

unsafe extern "C" fn destroyed(widget: Widget, _data: *mut c_void) {
    TARGETS.with(|targets| {
        if let Ok(mut targets) = targets.try_borrow_mut() {
            targets.remove(&(widget as usize));
        }
    });
}

// "clicked" of a button, "activate" of an item of a menu or of a field
unsafe extern "C" fn clicked(widget: Widget, _data: *mut c_void) {
    let target = TARGETS.with(|targets| targets.try_borrow().ok().and_then(|targets| targets.get(&(widget as usize)).cloned()));
    // a menu pops up during the click, which it needs on Wayland
    if matches!(target, Some(Target::Home(home::Action::More))) {
        home::more_menu();
        return;
    }
    let widget = widget as usize;
    later(move || dispatch(widget, None));
}

// "button-press-event" of a card
unsafe extern "C" fn pressed(widget: Widget, _event: *mut c_void, _data: *mut c_void) -> c_int {
    let widget = widget as usize;
    later(move || dispatch(widget, None));
    1
}

// "state-set" of a switch: the App decides, the switch follows its overview
unsafe extern "C" fn state_set(widget: Widget, state: c_int, _data: *mut c_void) -> c_int {
    if UPDATING.get() {
        return 0;
    }
    let widget = widget as usize;
    let on = state != 0;
    later(move || dispatch(widget, Some(on)));
    1
}

// "changed" of a field
unsafe extern "C" fn changed(widget: Widget, _data: *mut c_void) {
    let widget = widget as usize;
    later(move || dispatch(widget, None));
}

// "delete-event" of a window: the App closes it, as with Cancel; the main window hides
unsafe extern "C" fn delete_event(widget: Widget, _event: *mut c_void, _data: *mut c_void) -> c_int {
    let window = widget as usize;
    later(move || window_closed(window));
    1
}

// "draw" of the graph of the traffic
unsafe extern "C" fn draw(widget: Widget, cairo: *mut c_void, _data: *mut c_void) -> c_int {
    home::draw(widget, cairo);
    0
}

pub fn on_click(widget: Widget, target: Target) {
    remember(widget, target);
    gtk::connect(widget, "clicked", clicked as *const c_void, std::ptr::null_mut());
}

pub fn on_activate(widget: Widget, target: Target) {
    remember(widget, target);
    gtk::connect(widget, "activate", clicked as *const c_void, std::ptr::null_mut());
}

pub fn on_press(widget: Widget, target: Target) {
    remember(widget, target);
    gtk::connect(widget, "button-press-event", pressed as *const c_void, std::ptr::null_mut());
}

pub fn on_switch(widget: Widget, target: Target) {
    remember(widget, target);
    gtk::connect(widget, "state-set", state_set as *const c_void, std::ptr::null_mut());
}

pub fn on_change(widget: Widget, target: Target) {
    remember(widget, target);
    gtk::connect(widget, "changed", changed as *const c_void, std::ptr::null_mut());
}

pub fn on_close(window: Widget) {
    gtk::connect(window, "delete-event", delete_event as *const c_void, std::ptr::null_mut());
}

pub fn on_draw(widget: Widget) {
    gtk::connect(widget, "draw", draw as *const c_void, std::ptr::null_mut());
}

fn remember(widget: Widget, target: Target) {
    let known = TARGETS.with(|targets| targets.borrow_mut().insert(widget as usize, target).is_some());
    if !known {
        gtk::connect(widget, "destroy", destroyed as *const c_void, std::ptr::null_mut());
    }
}

// What the user did with a widget, out of the signal: `state`, the one asked of a switch
fn dispatch(widget: usize, state: Option<bool>) {
    let Some(target) = TARGETS.with(|targets| targets.borrow().get(&widget).cloned()) else { return };
    let window = window_id(gtk::toplevel(widget as Widget));
    match target {
        Target::Command(command) => run_command(command),
        Target::Home(home::Action::Switch(name)) => home::switched(&name, state.unwrap_or(false)),
        Target::Home(action) => home::run(action),
        Target::LoginConnect => {
            with_app(|app| app.submit(window));
        }
        Target::LoginCancel => {
            with_app(|app| app.cancel(window));
        }
        Target::LoginCode => {
            with_app(|app| app.code_changed(window));
        }
        Target::DetailsCopy => {
            with_app(|app| app.details_of(window).map(|details| details.copy_all()));
        }
        Target::DetailsClose => {
            with_app(|app| app.close_details(window));
        }
    }
    update();
}

fn window_closed(window: usize) {
    if home::is_home(window) {
        home::hide();
        return;
    }
    with_app(|app| {
        if app.login_of(window).is_some() {
            app.cancel(window);
        } else {
            app.close_details(window);
        }
    });
    update();
}

// The main window and the menu of the tray, as the App is now
fn update() {
    home::refresh();
    update_tray();
}

unsafe extern "C" fn tick(_data: *mut c_void) -> c_int {
    with_app(|app| app.tick());
    update();
    1
}

pub fn run_command(command: Command) {
    match command {
        Command::Open => open_home(),
        Command::Connect(name) => {
            with_app(|app| app.connect(&name));
        }
        Command::Disconnect(name) => {
            with_app(|app| app.disconnect(&name));
        }
        Command::LogIn(name) => {
            with_app(|app| app.show_login(&name, None));
        }
        Command::Import => flows::import_from_file(),
        Command::Remove(name) => flows::remove(&name),
        Command::Details(name) => {
            with_app(|app| app.show_details(&name));
        }
        Command::AppLog => {
            if let Some(path) = log::path() {
                setup::open_log(&path);
            }
        }
        Command::ServiceLog => setup::open_log(&crate::service::log_path()),
        Command::StartService => {
            if let Err(error) = setup::start_service() {
                flows::error_dialog(&error);
            }
            with_app(|app| app.list_soon());
        }
        Command::Quit => flows::quit(true),
    }
}

// the main window, then the login that waits, above it
fn open_home() {
    home::show();
    with_app(|app| app.show_pending());
}

// The tray: an icon of the theme for each state, installed with the app in the theme hicolor: authway-connected
fn icon_name(icon: Icon) -> String {
    let state = match icon {
        Icon::Idle => "idle",
        Icon::Connected => "connected",
        Icon::Attention => "attention",
        Icon::Refused => "refused",
    };
    format!("{}-{}", PRODUCT.to_lowercase(), state)
}

fn add_items(menu: Widget, items: &[MenuItem]) {
    for item in items {
        match item {
            MenuItem::Label(text) => {
                let entry = gtk::menu_item(text);
                gtk::set_sensitive(entry, false);
                gtk::append(menu, entry);
            }
            MenuItem::Action { text, command, .. } => {
                let entry = gtk::menu_item(text);
                on_activate(entry, Target::Command(command.clone()));
                gtk::append(menu, entry);
            }
            MenuItem::Switch { name, state, on, command } => {
                let title = if state.is_empty() { name.clone() } else { format!("{} ({})", name, state) };
                // checked before its signal, which the check would send
                let entry = gtk::check_menu_item(&title, *on);
                match command {
                    Some(command) => on_activate(entry, Target::Command(command.clone())),
                    None => gtk::set_sensitive(entry, false),
                }
                gtk::append(menu, entry);
            }
            MenuItem::Submenu { text, items } => {
                let submenu = gtk::menu();
                add_items(submenu, items);
                let entry = gtk::menu_item(text);
                gtk::set_submenu(entry, submenu);
                gtk::append(menu, entry);
            }
            MenuItem::Separator => gtk::append(menu, gtk::menu_separator()),
        }
    }
}

// the menu of the tray, made again when what it shows changed: the tray shows the one it was given
fn update_tray() {
    let Some(Some(indicator)) = with_app(|app| app.shell.indicator) else { return };
    let Some(items) = with_app(|app| app.menu()) else { return };
    let same = TRAY_MENU.with(|shown| shown.borrow().as_ref() == Some(&items));
    if same {
        return;
    }
    let Some(functions) = &gtk::libraries().indicator else { return };
    let menu = gtk::menu();
    add_items(menu, &items);
    unsafe { (functions.app_indicator_set_menu)(indicator, menu) };
    TRAY_MENU.with(|shown| *shown.borrow_mut() = Some(items));
}

unsafe extern "C" fn notice_clicked(_notification: *mut c_void, _action: *mut c_char, _data: *mut c_void) {
    later(|| {
        with_app(|app| app.balloon_clicked());
        update();
    });
}

// A notice of the desktop, as the balloons of Windows; a click on it is a click on the balloon. In the log only
// without libnotify.
fn post_notice(text: &str, warning: bool) {
    let Some(notify) = &gtk::libraries().notify else {
        log!("notice: {}", text);
        return;
    };
    unsafe {
        let icon = if warning { "dialog-warning" } else { "authway" };
        let notification = (notify.notify_notification_new)(c(PRODUCT).as_ptr(), c(text).as_ptr(), c(icon).as_ptr());
        if notification.is_null() {
            return;
        }
        let urgency = if warning { gtk::URGENCY_CRITICAL } else { gtk::URGENCY_NORMAL };
        (notify.notify_notification_set_urgency)(notification, urgency);
        (notify.notify_notification_add_action)(
            notification,
            c("default").as_ptr(),
            c(&strings::menu_open()).as_ptr(),
            notice_clicked as *const c_void,
            std::ptr::null_mut(),
            std::ptr::null(),
        );
        let mut error: *mut c_void = std::ptr::null_mut();
        if (notify.notify_notification_show)(notification, &mut error) == 0 && !error.is_null() {
            (g().g_error_free)(error);
        }
        // the one before goes; this one stays for a click on it
        let before = NOTICE.replace(notification);
        if !before.is_null() {
            (g().g_object_unref)(before);
        }
    }
}

pub struct LinuxShell {
    // the icon in the tray, None without the library of AppIndicator
    indicator: Option<*mut c_void>,
    // a tray shows the icon: else closing the main window says how to open it again
    pub has_tray: bool,
}

impl Shell for LinuxShell {
    type Login = login::LoginWindow;
    type Details = details::DetailsWindow;

    fn waker(&self) -> Waker {
        Arc::new(|| {
            later(|| {
                with_app(|app| app.drain());
                update();
            })
        })
    }

    fn show(&mut self, icon: Icon, tip: &str) {
        let (Some(indicator), Some(functions)) = (self.indicator, &gtk::libraries().indicator) else { return };
        unsafe {
            (functions.app_indicator_set_icon_full)(indicator, c(&icon_name(icon)).as_ptr(), c(tip).as_ptr());
            (functions.app_indicator_set_title)(indicator, c(tip).as_ptr());
        }
    }

    fn notify(&mut self, text: &str, warning: bool) {
        post_notice(text, warning);
    }

    fn open_login(&mut self, form: LoginForm) -> Option<login::LoginWindow> {
        Some(login::LoginWindow::open(form))
    }

    fn open_details(&mut self, tunnel: &str, details: Details) -> Option<details::DetailsWindow> {
        Some(details::DetailsWindow::open(tunnel, details))
    }

    fn import_later(&mut self) {
        later(flows::import_from_file);
    }

    fn has_main(&self) -> bool {
        true
    }

    // at the sign-in only if the user didn't turn it off, and always without a tray: the taskbar is the way to the app
    // then. Out of the App, which the window asks for its overview
    fn show_main(&mut self, startup: Startup) -> bool {
        if startup == Startup::SignIn && !settings::open_at_sign_in() && self.has_tray {
            return false;
        }
        later(open_home);
        true
    }
}

// the windows close, the icon goes; the tunnels are off
pub fn shutdown() {
    QUITTING.set(true);
    home::close();
    with_app(|app| {
        app.shutdown();
        if let (Some(indicator), Some(functions)) = (app.shell.indicator, &gtk::libraries().indicator) {
            unsafe { (functions.app_indicator_set_status)(indicator, 0) };
        }
    });
}

pub fn quit_main_loop() {
    unsafe { (g().gtk_main_quit)() };
}

// another start of the app by the same user: SIGUSR1 from it
unsafe extern "C" fn show_requested(_data: *mut c_void) -> c_int {
    with_app(|app| app.show_from_user());
    update();
    1
}

// the end of the session, or of the process: the tunnels go off with the app, and come back at the next start
unsafe extern "C" fn terminate(_data: *mut c_void) -> c_int {
    if !QUITTING.get() {
        log!("{} stops", PRODUCT);
        flows::stop_tunnels();
    }
    quit_main_loop();
    0
}

// Once per user: the lock goes with the process, its number in the file for the next start to call it
fn single_instance() -> Result<File, Option<i32>> {
    let folder = setup::user_data_dir();
    let _ = fs::create_dir_all(&folder);
    let mut file = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(folder.join("app.lock")).map_err(|_| None)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let mut text = String::new();
        let _ = file.read_to_string(&mut text);
        return Err(text.trim().parse().ok());
    }
    let _ = file.set_len(0);
    let _ = file.rewind();
    let _ = write!(file, "{}", std::process::id());
    Ok(file)
}

const CSS: &str = "
.authway-card { background-color: alpha(@theme_fg_color, 0.04); border: 1px solid alpha(@theme_fg_color, 0.12);
    border-radius: 10px; }
.authway-card:hover { background-color: alpha(@theme_fg_color, 0.07); }
.authway-box { background-color: alpha(@theme_fg_color, 0.03); border: 1px solid alpha(@theme_fg_color, 0.10);
    border-radius: 10px; }
.authway-banner { background-color: alpha(#e5a50a, 0.20); border-radius: 8px; }
.authway-name { font-weight: bold; font-size: 1.1em; }
.authway-heading { font-weight: bold; }
.authway-big { font-weight: bold; font-size: 1.4em; }
.authway-dim { opacity: 0.7; }
.authway-small { font-size: 0.9em; }
.authway-good { color: #26a269; }
.authway-warning { color: #c64600; }
.authway-bad { color: #c01c28; }
.authway-busy { color: #3584e4; }
.authway-off { opacity: 0.55; }
.authway-download { color: #3584e4; }
.authway-upload { color: #2190a4; }
";

pub fn run(startup: Startup) -> i32 {
    if let Err(error) = gtk::load() {
        eprintln!("{}: {}", PRODUCT, error);
        return 1;
    }
    if unsafe { (g().gtk_init_check)(std::ptr::null_mut(), std::ptr::null_mut()) } == 0 {
        eprintln!("{}: no display to open its window on", PRODUCT);
        return 1;
    }
    let lock = match single_instance() {
        Ok(lock) => lock,
        // already running for this user: it shows itself
        Err(Some(pid)) => {
            unsafe { libc::kill(pid, libc::SIGUSR1) };
            return 0;
        }
        Err(None) => {
            eprintln!("{}: can't write in {}", PRODUCT, setup::user_data_dir().display());
            return 1;
        }
    };
    log::init(setup::user_log());
    log!("{} {} started", PRODUCT, VERSION);
    gtk::load_css(CSS);
    let libraries = gtk::libraries();
    if let Some(notify) = &libraries.notify {
        unsafe { (notify.notify_init)(c(PRODUCT).as_ptr()) };
    }
    let has_tray = gtk::has_tray();
    let indicator = libraries.indicator.as_ref().map(|functions| unsafe {
        let id = c(&PRODUCT.to_lowercase());
        let indicator = (functions.app_indicator_new)(id.as_ptr(), c(&icon_name(Icon::Idle)).as_ptr(), gtk::INDICATOR_APPLICATION_STATUS);
        (functions.app_indicator_set_status)(indicator, gtk::INDICATOR_ACTIVE);
        (functions.app_indicator_set_title)(indicator, id.as_ptr());
        indicator
    });
    if indicator.is_none() || !has_tray {
        log!("no tray for the icon: the main window is the way to the app");
    }
    let shell = LinuxShell { indicator, has_tray: has_tray && indicator.is_some() };
    APP.with(|cell| *cell.borrow_mut() = Some(App::new(shell, startup)));
    with_app(|app| app.start());
    update_tray();
    unsafe {
        // every second, also while a dialog is open
        (g().g_timeout_add)(1000, tick as *const c_void, std::ptr::null_mut());
        (g().g_unix_signal_add)(libc::SIGUSR1, show_requested as *const c_void, std::ptr::null_mut());
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            (g().g_unix_signal_add)(signal, terminate as *const c_void, std::ptr::null_mut());
        }
        (g().gtk_main)();
    }
    drop(lock);
    0
}
