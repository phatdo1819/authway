// The icon next to the clock, with the App of client/ behind it: what Windows shows of it (the icon, its balloons,
// its menu, the login windows and the windows of details), and the messages of Windows that reach it

use std::cell::RefCell;
use std::mem::{size_of, zeroed};
use std::ptr;
use std::sync::{Arc, OnceLock};
use std::thread;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, HWND, LPARAM, LRESULT, POINT, WAIT_OBJECT_0, WPARAM};
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
    PostMessageW, RegisterClassExW, RegisterWindowMessageW, SetForegroundWindow, SetMenuDefaultItem, SetTimer,
    TrackPopupMenuEx, ENDSESSION_CLOSEAPP, HICON, HMENU, IMAGE_ICON, LR_DEFAULTCOLOR, MB_ICONERROR, MF_GRAYED,
    MF_POPUP, MF_SEPARATOR, MF_STRING, SM_CXSMICON, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_CONTEXTMENU,
    WM_ENDSESSION, WM_NULL, WM_TIMER, WNDCLASSEXW, WS_OVERLAPPED,
};

use super::connect::ConnectWindow;
use super::details::DetailsWindow;
use super::{flows, instance, message_box, message_loop, Startup, WM_APP_EVENT, WM_APP_IMPORT, WM_APP_QUIT, WM_APP_SHOW, WM_APP_TRAY};
use crate::client::details::Details;
use crate::client::{self, Command, Icon, LoginForm, MenuItem, Shell, Waker};
use crate::log;
use crate::names::{self, PRODUCT, VERSION};
use crate::setup;
use crate::win::{last_error, wide};

const CLASS: &str = "AuthwayTray";
const TIMER: usize = 1;
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;

pub type App = client::App<WinShell>;

// the resource of each icon, as build.rs embeds them
fn resource(icon: Icon) -> u16 {
    match icon {
        Icon::Idle => 2,
        Icon::Attention => 3,
        Icon::Connected => 4,
        Icon::Refused => 5,
    }
}

pub struct WinShell {
    hwnd: HWND,
    // in the order of Icon
    icons: [HICON; 4],
    // the taskbar has the icon: it loses it when explorer restarts
    added: bool,
}

fn copy_wide(target: &mut [u16], text: &str) {
    let text: Vec<u16> = text.encode_utf16().take(target.len() - 1).collect();
    target[..text.len()].copy_from_slice(&text);
    target[text.len()] = 0;
}

impl WinShell {
    fn new(hwnd: HWND) -> WinShell {
        let size = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, GetDpiForSystem()) };
        let load = |icon: Icon| unsafe {
            LoadImageW(instance(), resource(icon) as usize as _, IMAGE_ICON, size, size, LR_DEFAULTCOLOR) as HICON
        };
        WinShell {
            hwnd,
            icons: [load(Icon::Idle), load(Icon::Connected), load(Icon::Attention), load(Icon::Refused)],
            added: false,
        }
    }

    fn notify_data(&self) -> NOTIFYICONDATAW {
        let mut data: NOTIFYICONDATAW = unsafe { zeroed() };
        data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = self.hwnd;
        data.uID = 1;
        data
    }

    // the timer and the icon go, the App quits
    pub fn stop(&mut self) {
        unsafe { KillTimer(self.hwnd, TIMER) };
        let data = self.notify_data();
        unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
        self.added = false;
    }
}

impl Shell for WinShell {
    type Login = ConnectWindow;
    type Details = DetailsWindow;

    fn waker(&self) -> Waker {
        let hwnd = self.hwnd as usize;
        Arc::new(move || unsafe {
            PostMessageW(hwnd as HWND, WM_APP_EVENT, 0, 0);
        })
    }

    fn show(&mut self, icon: Icon, tip: &str) {
        let mut data = self.notify_data();
        data.uFlags = NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        data.hIcon = self.icons[icon as usize];
        copy_wide(&mut data.szTip, tip);
        if self.added {
            unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
            return;
        }
        data.uFlags |= NIF_MESSAGE;
        data.uCallbackMessage = WM_APP_TRAY;
        unsafe {
            Shell_NotifyIconW(NIM_ADD, &data);
            data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &data);
        }
        self.added = true;
    }

    fn notify(&mut self, text: &str, warning: bool) {
        let mut data = self.notify_data();
        data.uFlags = NIF_INFO;
        copy_wide(&mut data.szInfo, text);
        copy_wide(&mut data.szInfoTitle, PRODUCT);
        data.dwInfoFlags = if warning { NIIF_WARNING } else { NIIF_INFO };
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
    }

    fn open_login(&mut self, form: LoginForm) -> Option<ConnectWindow> {
        ConnectWindow::open(form.tunnel, form.heading, form.hint, form.saved, form.can_remember, form.otp_required, form.notice)
    }

    fn open_details(&mut self, tunnel: &str, details: Details) -> Option<DetailsWindow> {
        DetailsWindow::open(tunnel, details)
    }

    fn import_later(&mut self) {
        unsafe { PostMessageW(self.hwnd, WM_APP_IMPORT, 0, 0) };
    }
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

// the windows close, the icon goes
pub fn shutdown() {
    with_app(|app| {
        app.shutdown();
        app.shell.stop();
    });
}

// the items of the menu; each command at its place in the list, from 1
fn add_items(menu: HMENU, items: &[MenuItem], commands: &mut Vec<Command>, default: &mut Option<u32>) {
    for item in items {
        unsafe {
            match item {
                MenuItem::Label(text) => {
                    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, wide(text).as_ptr());
                }
                MenuItem::Action { text, command, default: is_default } => {
                    commands.push(command.clone());
                    let id = commands.len() as u32;
                    AppendMenuW(menu, MF_STRING, id as usize, wide(text).as_ptr());
                    if *is_default {
                        default.get_or_insert(id);
                    }
                }
                MenuItem::Submenu { text, items } => {
                    let submenu = CreatePopupMenu();
                    add_items(submenu, items, commands, default);
                    AppendMenuW(menu, MF_POPUP, submenu as usize, wide(text).as_ptr());
                }
                MenuItem::Separator => {
                    AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
                }
            }
        }
    }
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
    let Some(items) = with_app(|app| app.menu()) else { return };
    let mut commands = Vec::new();
    let mut default = None;
    let chosen = unsafe {
        let menu = CreatePopupMenu();
        add_items(menu, &items, &mut commands, &mut default);
        if let Some(id) = default {
            SetMenuDefaultItem(menu, id, 0);
        }
        let mut point = POINT { x: 0, y: 0 };
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
                    shutdown();
                }
            }
        }
        _ if message == taskbar_created() => {
            with_app(|app| {
                app.shell.added = false;
                app.refresh_icon();
            });
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
    APP.with(|cell| *cell.borrow_mut() = Some(App::new(WinShell::new(hwnd), startup)));
    with_app(|app| app.start());
    unsafe { SetTimer(hwnd, TIMER, 1000, None) };
    watch_events(hwnd);
    message_loop();
    APP.with(|cell| cell.borrow_mut().take());
    log!("{} quit", PRODUCT);
    unsafe { CloseHandle(mutex) };
    0
}
