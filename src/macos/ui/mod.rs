// The app in the menu bar, with AppKit: the state lives in one App (client/) on the main thread, reached through
// with_app(). The modal steps (alerts, the file panel, the password of an administrator) run outside of it, in
// flows.rs, so that the events that they let through find the App free; the same as on Windows.

pub mod details;
pub mod flows;
pub mod login;

use std::cell::{Cell, RefCell};
use std::fs::{self, File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject, Sel};
use objc2::{define_class, msg_send, sel, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAlert, NSAlertStyle, NSApplication, NSApplicationActivationPolicy, NSApplicationDelegate,
    NSApplicationTerminateReply, NSControlStateValueOn, NSControlTextEditingDelegate, NSImage, NSMenu, NSMenuDelegate,
    NSMenuItem,
    NSStatusBar, NSStatusItem, NSTextFieldDelegate, NSVariableStatusItemLength, NSView, NSWindow, NSWindowDelegate,
};
use objc2_foundation::{
    ns_string, NSActivityOptions, NSDistributedNotificationCenter, NSNotification, NSObject, NSObjectProtocol,
    NSProcessInfo, NSRunLoop, NSRunLoopCommonModes, NSString, NSTimer,
};

use crate::client::details::Details;
use crate::client::{self, Command, Icon, LoginForm, MenuItem, Shell, Waker};
use crate::log;
use crate::names::{self, PRODUCT, VERSION};
use crate::setup;

pub use crate::client::Startup;

mod notices;

pub type App = client::App<MacShell>;

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    // the commands of the menu that is open, by the tag of their item
    static COMMANDS: RefCell<Vec<Command>> = const { RefCell::new(Vec::new()) };
    // the app quits: the tunnels are already off
    static QUITTING: Cell<bool> = const { Cell::new(false) };
}

// The App, if it's free: None while a call on it is running, for the events that it causes itself
pub fn with_app<R>(action: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.with(|cell| {
        let mut guard = cell.try_borrow_mut().ok()?;
        let app = guard.as_mut()?;
        Some(action(app))
    })
}

// on the main thread, once the current event is done: out of the calls on the App
pub fn later(work: impl FnOnce() + Send + 'static) {
    DispatchQueue::main().exec_async(work);
}

pub fn ns(text: &str) -> Retained<NSString> {
    NSString::from_str(text)
}

// the id of a window, as the App knows it
pub fn window_id(window: &NSWindow) -> usize {
    window as *const NSWindow as usize
}

pub fn activate(mtm: MainThreadMarker) {
    #[allow(deprecated)]
    NSApplication::sharedApplication(mtm).activateIgnoringOtherApps(true);
}

// A message, with the buttons in their order: the index of the one pressed
pub fn alert(mtm: MainThreadMarker, text: &str, detail: Option<&str>, style: NSAlertStyle, buttons: &[&str]) -> usize {
    activate(mtm);
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&ns(text));
    if let Some(detail) = detail {
        alert.setInformativeText(&ns(detail));
    }
    alert.setAlertStyle(style);
    for button in buttons {
        alert.addButtonWithTitle(&ns(button));
    }
    (alert.runModal() - objc2_app_kit::NSAlertFirstButtonReturn).max(0) as usize
}

pub fn error_alert(mtm: MainThreadMarker, text: &str) {
    alert(mtm, text, None, NSAlertStyle::Warning, &["OK"]);
}

// The views of the windows, laid out from the top as on Windows
define_class!(
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[name = "AuthwayFlippedView"]
    pub struct FlippedView;

    impl FlippedView {
        #[unsafe(method(isFlipped))]
        fn is_flipped(&self) -> bool {
            true
        }
    }
);

impl FlippedView {
    pub fn new(mtm: MainThreadMarker) -> Retained<FlippedView> {
        unsafe { msg_send![FlippedView::alloc(mtm), init] }
    }
}

// What AppKit calls: the menu, the buttons and fields of the windows, the timer, the app itself
define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "AuthwayTarget"]
    pub struct Target;

    impl Target {
        #[unsafe(method(menuChosen:))]
        fn menu_chosen(&self, item: &NSMenuItem) {
            let command = COMMANDS.with(|commands| usize::try_from(item.tag()).ok().and_then(|tag| commands.borrow().get(tag).cloned()));
            if let Some(command) = command {
                // out of the menu, which is still closing
                later(move || run_command(command));
            }
        }

        #[unsafe(method(tick:))]
        fn tick(&self, _timer: &NSTimer) {
            with_app(|app| app.tick());
        }

        #[unsafe(method(connectPressed:))]
        fn connect_pressed(&self, sender: &NSView) {
            if let Some(id) = sender.window().map(|window| window_id(&window)) {
                with_app(|app| app.submit(id));
            }
        }

        #[unsafe(method(cancelPressed:))]
        fn cancel_pressed(&self, sender: &NSView) {
            if let Some(id) = sender.window().map(|window| window_id(&window)) {
                later(move || {
                    with_app(|app| app.cancel(id));
                });
            }
        }

        #[unsafe(method(copyPressed:))]
        fn copy_pressed(&self, sender: &NSView) {
            if let Some(id) = sender.window().map(|window| window_id(&window)) {
                with_app(|app| app.details_of(id).map(|window| window.copy_all()));
            }
        }

        #[unsafe(method(closePressed:))]
        fn close_pressed(&self, sender: &NSView) {
            if let Some(id) = sender.window().map(|window| window_id(&window)) {
                later(move || {
                    with_app(|app| app.close_details(id));
                });
            }
        }

        // another start of the app, by the same user
        #[unsafe(method(showRequested:))]
        fn show_requested(&self, _notification: &NSNotification) {
            with_app(|app| app.show_from_user());
        }
    }

    unsafe impl NSObjectProtocol for Target {}

    unsafe impl NSApplicationDelegate for Target {
        // Quit from the menu, the logout, or uninstall.sh: the tunnels go off with the app
        #[unsafe(method(applicationShouldTerminate:))]
        fn should_terminate(&self, _sender: &NSApplication) -> NSApplicationTerminateReply {
            if !QUITTING.get() {
                flows::stop_tunnels();
            }
            log!("{} quit", PRODUCT);
            NSApplicationTerminateReply::TerminateNow
        }

        // the app opened again from the Finder or Launchpad
        #[unsafe(method(applicationShouldHandleReopen:hasVisibleWindows:))]
        fn should_reopen(&self, _sender: &NSApplication, _visible: bool) -> bool {
            with_app(|app| app.show_from_user());
            false
        }
    }

    unsafe impl NSMenuDelegate for Target {
        // the menu of the icon, made again each time it opens
        #[unsafe(method(menuNeedsUpdate:))]
        fn menu_needs_update(&self, menu: &NSMenu) {
            let Some(items) = with_app(|app| app.menu()) else { return };
            menu.removeAllItems();
            let mut commands = Vec::new();
            add_items(self, menu, &items, &mut commands);
            COMMANDS.with(|cell| *cell.borrow_mut() = commands);
        }
    }

    unsafe impl NSWindowDelegate for Target {
        // the close button: the App closes the window, as with Cancel
        #[unsafe(method(windowShouldClose:))]
        fn window_should_close(&self, sender: &NSWindow) -> bool {
            let id = window_id(sender);
            later(move || {
                with_app(|app| {
                    if app.login_of(id).is_some() {
                        app.cancel(id);
                    } else {
                        app.close_details(id);
                    }
                });
            });
            false
        }
    }

    unsafe impl NSControlTextEditingDelegate for Target {
        // the field of the code: a pasted code, the sixth digit
        #[unsafe(method(controlTextDidChange:))]
        fn control_text_did_change(&self, notification: &NSNotification) {
            let window = notification.object().and_then(|object| object.downcast::<NSView>().ok()).and_then(|view| view.window());
            if let Some(id) = window.map(|window| window_id(&window)) {
                with_app(|app| app.code_changed(id));
            }
        }
    }

    unsafe impl NSTextFieldDelegate for Target {}
);

impl Target {
    fn new(mtm: MainThreadMarker) -> Retained<Target> {
        unsafe { msg_send![Target::alloc(mtm), init] }
    }

    pub fn object(&self) -> &AnyObject {
        self
    }
}

// the items of the menu; each command at its place in the list, its tag
fn add_items(target: &Target, menu: &NSMenu, items: &[MenuItem], commands: &mut Vec<Command>) {
    let mtm = target.mtm();
    for item in items {
        match item {
            MenuItem::Label(text) => {
                let entry = menu_item(mtm, text, None);
                entry.setEnabled(false);
                menu.addItem(&entry);
            }
            MenuItem::Action { text, command, .. } => {
                let entry = menu_item(mtm, text, Some(sel!(menuChosen:)));
                unsafe { entry.setTarget(Some(target.object())) };
                entry.setTag(commands.len() as isize);
                commands.push(command.clone());
                menu.addItem(&entry);
            }
            MenuItem::Switch { name, state, on, command } => {
                let title = if state.is_empty() { name.clone() } else { format!("{} ({})", name, state) };
                let entry = menu_item(mtm, &title, command.as_ref().map(|_| sel!(menuChosen:)));
                if *on {
                    entry.setState(NSControlStateValueOn);
                }
                match command {
                    Some(command) => {
                        unsafe { entry.setTarget(Some(target.object())) };
                        entry.setTag(commands.len() as isize);
                        commands.push(command.clone());
                    }
                    None => entry.setEnabled(false),
                }
                menu.addItem(&entry);
            }
            MenuItem::Submenu { text, items } => {
                let submenu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &ns(text));
                submenu.setAutoenablesItems(false);
                add_items(target, &submenu, items, commands);
                let entry = menu_item(mtm, text, None);
                entry.setSubmenu(Some(&submenu));
                menu.addItem(&entry);
            }
            MenuItem::Separator => menu.addItem(&NSMenuItem::separatorItem(mtm)),
        }
    }
}

pub fn menu_item(mtm: MainThreadMarker, title: &str, action: Option<Sel>) -> Retained<NSMenuItem> {
    unsafe { NSMenuItem::initWithTitle_action_keyEquivalent(NSMenuItem::alloc(mtm), &ns(title), action, ns_string!("")) }
}

fn run_command(command: Command) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    match command {
        // the menu bar is all there is on macOS
        Command::Open => {}
        Command::Connect(name) => {
            with_app(|app| app.connect(&name));
        }
        Command::Disconnect(name) => {
            with_app(|app| app.disconnect(&name));
        }
        Command::LogIn(name) => {
            with_app(|app| app.show_login(&name, None));
        }
        Command::Import => flows::import_from_file(mtm),
        Command::Remove(name) => flows::remove(mtm, &name),
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
            match setup::start_service() {
                Ok(()) => {}
                Err(error) if error == setup::CANCELLED => {}
                Err(error) => error_alert(mtm, &error),
            }
            with_app(|app| app.list_soon());
        }
        Command::Quit => flows::quit(mtm, true),
    }
}

// The menus of the app, for the keys of the windows: without them, Cmd+V doesn't paste a code
fn main_menu(mtm: MainThreadMarker) -> Retained<NSMenu> {
    let item = |title: &str, action: Sel, key: &str| unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(NSMenuItem::alloc(mtm), &ns(title), Some(action), &ns(key))
    };
    let submenu = |title: &str, items: Vec<Retained<NSMenuItem>>| {
        let menu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &ns(title));
        for entry in items {
            menu.addItem(&entry);
        }
        let entry = menu_item(mtm, title, None);
        entry.setSubmenu(Some(&menu));
        entry
    };
    let main = NSMenu::new(mtm);
    main.addItem(&submenu(PRODUCT, vec![]));
    main.addItem(&submenu(
        "Edit",
        vec![
            item("Undo", sel!(undo:), "z"),
            item("Redo", sel!(redo:), "Z"),
            NSMenuItem::separatorItem(mtm),
            item("Cut", sel!(cut:), "x"),
            item("Copy", sel!(copy:), "c"),
            item("Paste", sel!(paste:), "v"),
            item("Select All", sel!(selectAll:), "a"),
        ],
    ));
    main.addItem(&submenu("Window", vec![item("Close", sel!(performClose:), "w")]));
    main
}

// SF Symbols, drawn by macOS in the colors of the menu bar
fn symbol(icon: Icon) -> &'static NSString {
    match icon {
        Icon::Idle => ns_string!("lock.shield"),
        Icon::Connected => ns_string!("lock.shield.fill"),
        Icon::Attention => ns_string!("exclamationmark.shield"),
        Icon::Refused => ns_string!("xmark.shield"),
    }
}

pub struct MacShell {
    mtm: MainThreadMarker,
    status: Retained<NSStatusItem>,
    target: Retained<Target>,
}

impl Shell for MacShell {
    type Login = login::LoginWindow;
    type Details = details::DetailsWindow;

    fn waker(&self) -> Waker {
        Arc::new(|| {
            later(|| {
                with_app(|app| app.drain());
            })
        })
    }

    fn show(&mut self, icon: Icon, tip: &str) {
        let Some(button) = self.status.button(self.mtm) else { return };
        match NSImage::imageWithSystemSymbolName_accessibilityDescription(symbol(icon), Some(&ns(PRODUCT))) {
            Some(image) => {
                image.setTemplate(true);
                button.setImage(Some(&image));
            }
            None => button.setTitle(&ns(PRODUCT)),
        }
        button.setToolTip(Some(&ns(tip)));
    }

    fn notify(&mut self, text: &str, warning: bool) {
        notices::post(text, warning);
    }

    fn open_login(&mut self, form: LoginForm) -> Option<login::LoginWindow> {
        login::LoginWindow::open(self.mtm, &self.target, form)
    }

    fn open_details(&mut self, tunnel: &str, details: Details) -> Option<details::DetailsWindow> {
        details::DetailsWindow::open(self.mtm, &self.target, tunnel, details)
    }

    fn import_later(&mut self) {
        later(|| {
            if let Some(mtm) = MainThreadMarker::new() {
                flows::import_from_file(mtm);
            }
        });
    }
}

// the windows close, the icon goes; the tunnels are off
pub fn shutdown() {
    QUITTING.set(true);
    with_app(|app| {
        app.shutdown();
        NSStatusBar::systemStatusBar().removeStatusItem(&app.shell.status);
    });
}

// the notification that another start of the app sends to the one running, for this user only
fn show_notification() -> Retained<NSString> {
    let suffix = if cfg!(feature = "testing") { ".test" } else { "" };
    ns(&format!("{}{}.show.{}", names::BUNDLE_ID, suffix, unsafe { libc::getuid() }))
}

// once per user: the lock goes with the process
fn single_instance() -> Option<File> {
    let folder = setup::user_data_dir();
    let _ = fs::create_dir_all(&folder);
    let file = OpenOptions::new().create(true).truncate(false).write(true).open(folder.join("app.lock")).ok()?;
    (unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0).then_some(file)
}

pub fn run(startup: Startup) -> i32 {
    let Some(mtm) = MainThreadMarker::new() else { return 1 };
    if !cfg!(feature = "testing") && !setup::is_installed_copy() {
        return flows::start_installed(mtm);
    }
    let Some(lock) = single_instance() else {
        // already running for this user: it shows itself
        let center = NSDistributedNotificationCenter::defaultCenter();
        unsafe { center.postNotificationName_object_userInfo_deliverImmediately(&show_notification(), None, None, true) };
        return 0;
    };
    log::init(setup::user_log());
    log!("{} {} started", PRODUCT, VERSION);
    let application = NSApplication::sharedApplication(mtm);
    application.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    let target = Target::new(mtm);
    application.setDelegate(Some(ProtocolObject::from_ref(&*target)));
    application.setMainMenu(Some(&main_menu(mtm)));
    let status = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
    let menu = NSMenu::new(mtm);
    menu.setAutoenablesItems(false);
    menu.setDelegate(Some(ProtocolObject::from_ref(&*target)));
    status.setMenu(Some(&menu));
    notices::setup();
    let shell = MacShell { mtm, status, target: target.clone() };
    APP.with(|cell| *cell.borrow_mut() = Some(App::new(shell, startup)));
    with_app(|app| app.start());
    // every second, also while a menu or a modal window is open
    let timer = unsafe {
        NSTimer::timerWithTimeInterval_target_selector_userInfo_repeats(1.0, target.object(), sel!(tick:), None, true)
    };
    unsafe { NSRunLoop::mainRunLoop().addTimer_forMode(&timer, NSRunLoopCommonModes) };
    unsafe {
        NSDistributedNotificationCenter::defaultCenter().addObserver_selector_name_object(
            target.object(),
            sel!(showRequested:),
            Some(&show_notification()),
            None,
        )
    };
    // App Nap would slow down the timer of an app without windows: the logins and the list that keeps the tunnels on
    let _activity = NSProcessInfo::processInfo().beginActivityWithOptions_reason(
        NSActivityOptions::UserInitiatedAllowingIdleSystemSleep,
        &ns("watches the VPN sessions"),
    );
    application.run();
    // run() ends the process on terminate: this is for the tests that stop it
    drop(lock);
    0
}
