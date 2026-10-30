// The main window, the face of the app on the desktop: a card for each VPN with its switch, its state and, while
// it's on, its traffic; "Add VPN", or a .conf dropped on the window, adds one. A card opens the page of its VPN: its
// traffic over the last minutes, its name and its login to change, all its details and the way to remove it.
// Closing the window leaves the app next to the clock.
//
// It's a view of the App, which it asks for an overview every second; its buttons do what the menu of the icon
// does. They are buttons of Windows drawn here, so Tab, Space, Enter and the screen readers know them. The window
// lives apart from the App, in HOME: the App is busy while its calls open windows, and the window paints meanwhile.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::mem::{replace, size_of, zeroed};
use std::ptr;
use std::sync::Once;
use std::time::Instant;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, DeleteObject, EndPaint, GetDC, GetMonitorInfoW, InvalidateRect, MonitorFromPoint, MonitorFromRect,
    RedrawWindow, ReleaseDC, SetBkColor, SetTextColor, DT_CENTER, DT_END_ELLIPSIS, DT_LEFT, DT_RIGHT, DT_SINGLELINE,
    DT_VCENTER, DT_WORDBREAK, HBRUSH, HDC, HGDIOBJ, MONITORINFO, MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTONULL,
    PAINTSTRUCT, RDW_ALLCHILDREN, RDW_INVALIDATE,
};
use windows_sys::Win32::UI::Controls::{
    SetScrollInfo, DRAWITEMSTRUCT, EM_SETLIMITTEXT, EM_SETREADONLY, ODS_DISABLED, ODS_FOCUS, ODS_NOFOCUSRECT, ODS_SELECTED,
    TOOLTIPS_CLASSW, TTF_IDISHWND, TTF_SUBCLASS, TTM_ADDTOOLW, TTS_ALWAYSTIP, TTS_NOPREFIX, TTTOOLINFOW, WM_MOUSELEAVE,
};
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, IsWindowEnabled, SetFocus, TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT,
};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, DragFinish, DragQueryFileW, RemoveWindowSubclass, SetWindowSubclass, HDROP};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow,
    DrawIconEx, GetClientRect, GetCursorPos, GetParent, GetScrollInfo, GetWindowRect, IsIconic,
    IsWindowVisible, IsZoomed, LoadCursorW, LoadImageW, PostMessageW, RegisterClassExW, SendMessageW, SetCursor,
    SetForegroundWindow, SetWindowPos, ShowWindow, TrackPopupMenuEx, BN_CLICKED,
    BS_OWNERDRAW, CW_USEDEFAULT, DI_NORMAL, EN_CHANGE, EN_KILLFOCUS, EN_SETFOCUS, ES_AUTOHSCROLL, HICON, HMENU,
    HWND_TOP, IDCANCEL, IDC_ARROW, IDC_HAND, IDOK, IMAGE_ICON, LR_DEFAULTCOLOR, MB_ICONERROR, MF_CHECKED, MF_GRAYED,
    MF_POPUP, MF_SEPARATOR, MF_STRING, MINMAXINFO, SB_BOTTOM, SB_LINEDOWN, SB_LINEUP, SB_PAGEDOWN, SB_PAGEUP,
    SB_THUMBTRACK, SB_TOP, SB_VERT, SCROLLINFO, SIF_PAGE, SIF_POS, SIF_RANGE, SIF_TRACKPOS, SWP_NOACTIVATE,
    SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SW_HIDE, SW_RESTORE, SW_SHOW, TPM_RETURNCMD, TPM_RIGHTALIGN, TPM_TOPALIGN,
    WM_APP, WM_CLOSE, WM_COMMAND, WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED, WM_DRAWITEM,
    WM_DROPFILES, WM_ERASEBKGND, WM_GETMINMAXINFO, WM_KEYDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_MOUSEWHEEL,
    WM_NCDESTROY, WM_PAINT, WM_SETCURSOR, WM_SETFOCUS, WM_SETTINGCHANGE, WM_SIZE, WM_SYSCOLORCHANGE, WM_VSCROLL,
    WNDCLASSEXW, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_EX_ACCEPTFILES, WS_EX_APPWINDOW, WS_EX_CONTROLPARENT,
    WS_EX_TOPMOST, WS_OVERLAPPEDWINDOW, WS_POPUP, WS_TABSTOP, WS_VSCROLL,
};

use super::flows;
use super::theme::{self, point, rgb, Buffer, Canvas, Font, Fonts, Palette};
use super::tray::with_app;
use super::{add_dialog, child, get_text, instance, message_box, open_in_notepad, remove_dialog, scale, set_font, set_text};
use crate::api::Page as LoginPage;
use crate::client::details::handshake_text;
use crate::client::overview::{Card, History, Overview, Tone, Traffic, SAMPLES};
use crate::client::{ServiceState, Shell};
use crate::conf::MAX_NAME_LENGTH;
use crate::creds;
use crate::log;
use crate::names::{PRODUCT, VERSION};
use crate::settings;
use crate::setup;
use crate::strings;
use crate::time::unix_now;
use crate::win::wide;

const CLASS: &str = "AuthwayHome";
const PANEL_CLASS: &str = "AuthwayHomePanel";
const STYLE: u32 = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
const EX_STYLE: u32 = WS_EX_APPWINDOW | WS_EX_CONTROLPARENT | WS_EX_ACCEPTFILES;

// in pixels at 100%
const WIDTH: i32 = 420;
const HEIGHT: i32 = 640;
const MIN_WIDTH: i32 = 360;
const MIN_HEIGHT: i32 = 440;
const HEADER: i32 = 60;
const BANNER: i32 = 48;
const MARGIN: i32 = 16;
const GAP: i32 = 10;
const PAD: i32 = 16;
const RADIUS: i32 = 10;
const BUTTON_RADIUS: i32 = 8;
const SWITCH_WIDTH: i32 = 40;
const SWITCH_HEIGHT: i32 = 22;
const ICON_BUTTON: i32 = 36;
const BUTTON_HEIGHT: i32 = 32;
const FIELD_HEIGHT: i32 = 34;
const GRAPH_HEIGHT: i32 = 76;
const SCROLL_LINE: i32 = 48;

// a paint that found the window busy, done again
const WM_APP_REDRAW: u32 = WM_APP + 20;
// the mouse moved on a button
const WM_APP_HOVER: u32 = WM_APP + 21;
// a button got the focus: into view
const WM_APP_REVEAL: u32 = WM_APP + 22;

// the menu of "More"
const MENU_ADD: usize = 1;
const MENU_SIGN_IN: usize = 2;
const MENU_APP_LOG: usize = 3;
const MENU_SERVICE_LOG: usize = 4;
const MENU_START_SERVICE: usize = 5;
const MENU_QUIT: usize = 6;

#[derive(Clone, PartialEq, Eq, Debug)]
enum View {
    List,
    // the page of a VPN, by its name
    Vpn(String),
}

// what each button is
#[derive(Clone, PartialEq, Eq, Debug)]
enum Kind {
    More,
    Back,
    Add,
    StartService,
    EmptyAdd,
    // a card: it opens the page of its VPN, or turns it on or off at its switch, or logs in at its button
    Card(String),
    // the page of a VPN
    Switch,
    LogIn,
    Forget,
    Save,
    Details,
    Remove,
}

impl Kind {
    // in the header, else in the panel under it
    fn in_header(&self) -> bool {
        matches!(self, Kind::More | Kind::Back | Kind::Add | Kind::StartService)
    }
}

// where the mouse, or the click, is on a card
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Part {
    Nothing,
    Body,
    Switch,
    LogIn,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Primary,
    Secondary,
    Danger,
    Link,
    Caution,
}

enum Action {
    // the menu, under its button
    More(HWND),
    Back,
    Add,
    StartService,
    Open(String),
    // the name, and whether it's on
    Toggle(String, bool),
    LogIn(String),
    Forget,
    Save,
    Details(String),
    Remove(String),
}

struct Item {
    hwnd: HWND,
    kind: Kind,
}

// The places on a card, in the card
struct CardShape {
    name: String,
    switch: RECT,
    log_in: Option<RECT>,
    text_right: i32,
    name_top: i32,
    sub_top: i32,
    state_top: i32,
    traffic_top: Option<i32>,
    hint: Option<RECT>,
}

// what the panel draws, in its coordinates without the scroll
enum Shape {
    // a white card
    Panel(RECT),
    Text { rect: RECT, font: Font, color: u32, text: String, format: u32 },
    Dot { x: i32, y: i32, radius: i32, color: u32 },
    Circle { rect: RECT, color: u32 },
    Graph(RECT),
    // the frame of a text field
    Field(RECT, HWND),
}

// the page of a VPN: its fields stay while the overview changes under them
struct VpnPage {
    name: String,
    name_edit: HWND,
    // null without a login page
    user_edit: HWND,
    login: Option<LoginPage>,
    saved_user: String,
    saved_password: bool,
    name_locked: bool,
}

struct Changes {
    name: String,
    new_name: Option<String>,
    username: Option<(LoginPage, String)>,
}

pub struct Home {
    hwnd: HWND,
    panel: HWND,
    tooltip: HWND,
    dpi: u32,
    fonts: Fonts,
    palette: Palette,
    surface_brush: HBRUSH,
    background_brush: HBRUSH,
    icon: HICON,
    overview: Overview,
    view: View,
    items: Vec<Item>,
    page: Option<VpnPage>,
    history: HashMap<String, History>,
    cards: Vec<CardShape>,
    shapes: Vec<Shape>,
    // where the children go in the panel, without the scroll
    places: Vec<(HWND, RECT)>,
    scroll: i32,
    content: i32,
    // the scroll of the list, while a page is open
    list_scroll: i32,
}

thread_local! {
    static HOME: RefCell<Option<Home>> = const { RefCell::new(None) };
    // the button under the mouse, and where on it
    static HOT: Cell<(HWND, POINT)> = const { Cell::new((ptr::null_mut(), POINT { x: 0, y: 0 })) };
    // the part of the card under the mouse, as last drawn
    static HOT_PART: Cell<(HWND, Part)> = const { Cell::new((ptr::null_mut(), Part::Nothing)) };
    // where the last click on a button was; None for the keyboard
    static CLICK: Cell<Option<(HWND, POINT)>> = const { Cell::new(None) };
}

fn with_home<R>(action: impl FnOnce(&mut Home) -> R) -> Option<R> {
    HOME.with(|cell| {
        let mut guard = cell.try_borrow_mut().ok()?;
        Some(action(guard.as_mut()?))
    })
}

fn with_home_ref<R>(action: impl FnOnce(&Home) -> R) -> Option<R> {
    HOME.with(|cell| {
        let guard = cell.try_borrow().ok()?;
        Some(action(guard.as_ref()?))
    })
}

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
    RECT { left, top, right, bottom }
}

fn shifted(rect: &RECT, x: i32, y: i32) -> RECT {
    RECT { left: rect.left + x, top: rect.top + y, right: rect.right + x, bottom: rect.bottom + y }
}

fn inset(rect: &RECT, by: i32) -> RECT {
    RECT { left: rect.left + by, top: rect.top + by, right: rect.right - by, bottom: rect.bottom - by }
}

fn contains(rect: &RECT, point: POINT) -> bool {
    point.x >= rect.left && point.x < rect.right && point.y >= rect.top && point.y < rect.bottom
}

fn client_size(window: HWND) -> (i32, i32) {
    let mut client: RECT = unsafe { zeroed() };
    unsafe { GetClientRect(window, &mut client) };
    (client.right, client.bottom)
}

fn mix(from: u32, to: u32, amount: f32) -> u32 {
    let channel = |shift: u32| {
        let (a, b) = ((from >> shift) & 0xff, (to >> shift) & 0xff);
        ((a as f32 + (b as f32 - a as f32) * amount).round() as u32) << shift
    };
    channel(0) | channel(8) | channel(16)
}

fn low_word(value: usize) -> u32 {
    (value & 0xffff) as u32
}

fn point_of(lparam: LPARAM) -> POINT {
    POINT { x: (lparam & 0xffff) as i16 as i32, y: ((lparam >> 16) & 0xffff) as i16 as i32 }
}

fn register_classes() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| unsafe {
        for (name, procedure) in [(CLASS, window_proc as _), (PANEL_CLASS, panel_proc as _)] {
            let class = wide(name);
            let mut info: WNDCLASSEXW = zeroed();
            info.cbSize = size_of::<WNDCLASSEXW>() as u32;
            info.lpfnWndProc = Some(procedure);
            info.hInstance = instance();
            info.hCursor = LoadCursorW(ptr::null_mut(), IDC_ARROW);
            if name == CLASS {
                info.hIcon = LoadImageW(instance(), 1 as _, IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR) as _;
                info.hIconSm = LoadImageW(instance(), 1 as _, IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR) as _;
            }
            info.lpszClassName = class.as_ptr();
            if RegisterClassExW(&info) == 0 {
                log!("can't register the main window: {}", crate::win::last_error_message());
            }
        }
    });
}

fn load_icon(dpi: u32) -> HICON {
    let size = scale(24, dpi);
    unsafe { LoadImageW(instance(), 1 as _, IMAGE_ICON, size, size, LR_DEFAULTCOLOR) as HICON }
}

impl Home {
    fn open(overview: Overview) -> Option<Home> {
        register_classes();
        let hwnd = unsafe {
            CreateWindowExW(
                EX_STYLE,
                wide(CLASS).as_ptr(),
                wide(PRODUCT).as_ptr(),
                STYLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                200,
                200,
                ptr::null_mut(),
                ptr::null_mut(),
                instance(),
                ptr::null(),
            )
        };
        if hwnd.is_null() {
            log!("can't open the main window: {}", crate::win::last_error_message());
            return None;
        }
        let panel = child(hwnd, PANEL_CLASS, "", WS_VSCROLL | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, WS_EX_CONTROLPARENT, 0);
        let tooltip = unsafe {
            CreateWindowExW(
                WS_EX_TOPMOST,
                TOOLTIPS_CLASSW,
                ptr::null(),
                WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                hwnd,
                ptr::null_mut(),
                instance(),
                ptr::null(),
            )
        };
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        let palette = Palette::system();
        let mut home = Home {
            hwnd,
            panel,
            tooltip,
            dpi,
            fonts: Fonts::new(dpi),
            surface_brush: theme::brush(palette.surface),
            background_brush: theme::brush(palette.background),
            palette,
            icon: load_icon(dpi),
            overview,
            view: View::List,
            items: Vec::new(),
            page: None,
            history: HashMap::new(),
            cards: Vec::new(),
            shapes: Vec::new(),
            places: Vec::new(),
            scroll: 0,
            content: 0,
            list_scroll: 0,
        };
        home.place_window();
        home.sync();
        home.layout();
        add_dialog(hwnd);
        Some(home)
    }

    // where the user left it, if it's still on a display; else in the middle of the one with the mouse
    fn place_window(&self) {
        if let Some([left, top, width, height]) = settings::window_place() {
            let place = rect(left, top, left + width, top + height);
            if width > 0 && height > 0 && !unsafe { MonitorFromRect(&place, MONITOR_DEFAULTTONULL) }.is_null() {
                unsafe { SetWindowPos(self.hwnd, ptr::null_mut(), left, top, width, height, SWP_NOZORDER | SWP_NOACTIVATE) };
                return;
            }
        }
        let mut cursor = POINT { x: 0, y: 0 };
        let mut monitor: MONITORINFO = unsafe { zeroed() };
        monitor.cbSize = size_of::<MONITORINFO>() as u32;
        unsafe {
            GetCursorPos(&mut cursor);
            GetMonitorInfoW(MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST), &mut monitor);
        }
        let work = monitor.rcWork;
        let mut size = rect(0, 0, scale(WIDTH, self.dpi), scale(HEIGHT, self.dpi));
        unsafe { AdjustWindowRectExForDpi(&mut size, STYLE, 0, EX_STYLE, self.dpi) };
        let width = (size.right - size.left).min(work.right - work.left);
        let height = (size.bottom - size.top).min(work.bottom - work.top);
        let x = work.left + (work.right - work.left - width) / 2;
        let y = work.top + (work.bottom - work.top - height) / 2;
        unsafe { SetWindowPos(self.hwnd, ptr::null_mut(), x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE) };
    }

    fn save_place(&self) {
        unsafe {
            if IsIconic(self.hwnd) != 0 || IsZoomed(self.hwnd) != 0 || IsWindowVisible(self.hwnd) == 0 {
                return;
            }
            let mut window: RECT = zeroed();
            GetWindowRect(self.hwnd, &mut window);
            settings::set_window_place([window.left, window.top, window.right - window.left, window.bottom - window.top]);
        }
    }

    fn s(&self, value: i32) -> i32 {
        scale(value, self.dpi)
    }

    fn visible(&self) -> bool {
        unsafe { IsWindowVisible(self.hwnd) != 0 }
    }

    // the overview of the App: what changed is drawn again
    fn update(&mut self, overview: Overview) {
        let now = Instant::now();
        for card in &overview.cards {
            match &card.traffic {
                Some(traffic) => self.history.entry(card.name.clone()).or_default().add(now, traffic.rx_bytes, traffic.tx_bytes),
                None => {
                    self.history.remove(&card.name);
                }
            }
        }
        self.history.retain(|name, _| overview.card(name).is_some());
        let changed = overview != self.overview;
        let ticking = overview.cards.iter().any(|card| card.traffic.is_some());
        self.overview = overview;
        if let View::Vpn(name) = &self.view {
            if self.overview.card(name).is_none() {
                self.close_page();
                self.view = View::List;
                self.scroll = self.list_scroll;
                unsafe { InvalidateRect(self.hwnd, ptr::null(), 0) };
            }
        }
        if !self.visible() {
            return;
        }
        if changed {
            self.sync();
            self.layout();
        }
        // the durations and the graph move every second
        if changed || ticking {
            unsafe { RedrawWindow(self.panel, ptr::null(), ptr::null_mut(), RDW_INVALIDATE | RDW_ALLCHILDREN) };
        }
    }

    fn card(&self) -> Option<&Card> {
        match &self.view {
            View::Vpn(name) => self.overview.card(name),
            View::List => None,
        }
    }

    // the buttons that the view has, in the order of Tab
    fn wanted(&self) -> Vec<Kind> {
        let mut kinds = Vec::new();
        match &self.view {
            View::List => kinds.extend([Kind::Add, Kind::More]),
            View::Vpn(_) => kinds.extend([Kind::Back, Kind::More]),
        }
        if self.overview.service == ServiceState::Unavailable {
            kinds.push(Kind::StartService);
        }
        match &self.view {
            View::List => {
                kinds.extend(self.overview.cards.iter().map(|card| Kind::Card(card.name.clone())));
                let known = !matches!(self.overview.service, ServiceState::Unknown | ServiceState::Unavailable);
                if self.overview.cards.is_empty() && known {
                    kinds.push(Kind::EmptyAdd);
                }
            }
            View::Vpn(_) => {
                if let Some(card) = self.card() {
                    kinds.push(Kind::Switch);
                    if card.needs_login {
                        kinds.push(Kind::LogIn);
                    }
                    if self.page.as_ref().is_some_and(|page| page.saved_password && !page.user_edit.is_null()) {
                        kinds.push(Kind::Forget);
                    }
                    kinds.extend([Kind::Save, Kind::Details, Kind::Remove]);
                }
            }
        }
        kinds
    }

    fn label(&self, kind: &Kind) -> String {
        match kind {
            Kind::More => strings::HOME_MORE.to_string(),
            Kind::Back => strings::HOME_BACK.to_string(),
            Kind::Add => strings::HOME_ADD.to_string(),
            Kind::StartService => strings::HOME_START_SERVICE.to_string(),
            Kind::EmptyAdd => strings::HOME_EMPTY_ADD.to_string(),
            Kind::Card(name) => match self.overview.card(name) {
                Some(card) => format!("{}: {}", card.name, card.state),
                None => name.clone(),
            },
            Kind::Switch => match self.card() {
                Some(card) => strings::home_switch(&card.name, card.on),
                None => String::new(),
            },
            Kind::LogIn => strings::HOME_LOG_IN.to_string(),
            Kind::Forget => strings::HOME_FORGET.to_string(),
            Kind::Save => strings::HOME_SAVE.to_string(),
            Kind::Details => strings::HOME_ALL_DETAILS.to_string(),
            Kind::Remove => strings::HOME_REMOVE.to_string(),
        }
    }

    fn add_tip(&self, button: HWND, text: &str) {
        let mut text = wide(text);
        let mut info: TTTOOLINFOW = unsafe { zeroed() };
        info.cbSize = size_of::<TTTOOLINFOW>() as u32;
        info.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
        info.hwnd = self.hwnd;
        info.uId = button as usize;
        info.lpszText = text.as_mut_ptr();
        unsafe { SendMessageW(self.tooltip, TTM_ADDTOOLW, 0, &info as *const _ as LPARAM) };
    }

    // The buttons of the view: the ones kept keep the focus, the others go or come, then all in the order of Tab
    fn sync(&mut self) {
        let wanted = self.wanted();
        let mut kept = Vec::new();
        for item in std::mem::take(&mut self.items) {
            if wanted.contains(&item.kind) {
                kept.push(item);
            } else {
                unsafe { DestroyWindow(item.hwnd) };
            }
        }
        for kind in &wanted {
            let position = kept.iter().position(|item| item.kind == *kind);
            let item = match position {
                Some(position) => kept.remove(position),
                None => {
                    let parent = if kind.in_header() { self.hwnd } else { self.panel };
                    let style = WS_TABSTOP | BS_OWNERDRAW as u32 | WS_CLIPSIBLINGS;
                    let hwnd = child(parent, "BUTTON", &self.label(kind), style, 0, 0);
                    unsafe { SetWindowSubclass(hwnd, Some(button_proc), 1, 0) };
                    if matches!(kind, Kind::More | Kind::Back) {
                        self.add_tip(hwnd, &self.label(kind));
                    }
                    if *kind == Kind::Save {
                        unsafe { EnableWindow(hwnd, 0) };
                    }
                    Item { hwnd, kind: kind.clone() }
                }
            };
            let label = self.label(kind);
            if get_text(item.hwnd) != label {
                set_text(item.hwnd, &label);
            }
            self.items.push(item);
        }
        // the header first, then the panel; the fields of a page after its switch and its login
        let mut previous = HWND_TOP;
        let header: Vec<HWND> = self.items.iter().filter(|item| item.kind.in_header()).map(|item| item.hwnd).collect();
        for hwnd in header.into_iter().chain([self.panel]) {
            unsafe { SetWindowPos(hwnd, previous, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) };
            previous = hwnd;
        }
        let mut order: Vec<HWND> = Vec::new();
        for item in self.items.iter().filter(|item| !item.kind.in_header()) {
            if item.kind == Kind::Forget || (item.kind == Kind::Save && !order.is_empty()) {
                if let Some(page) = &self.page {
                    for field in [page.name_edit, page.user_edit] {
                        if !field.is_null() && !order.contains(&field) {
                            order.push(field);
                        }
                    }
                }
            }
            order.push(item.hwnd);
        }
        let mut previous = HWND_TOP;
        for hwnd in order {
            unsafe { SetWindowPos(hwnd, previous, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) };
            previous = hwnd;
        }
        if let (Some(page), Some(card)) = (self.page.as_mut(), self.overview.card(match &self.view {
            View::Vpn(name) => name,
            View::List => "",
        })) {
            let locked = card.on || !card.can_switch;
            if locked != page.name_locked {
                page.name_locked = locked;
                unsafe { SendMessageW(page.name_edit, EM_SETREADONLY, locked as usize, 0) };
            }
        }
        self.update_save();
    }

    fn item(&self, kind: &Kind) -> Option<HWND> {
        self.items.iter().find(|item| item.kind == *kind).map(|item| item.hwnd)
    }

    fn kind_of(&self, hwnd: HWND) -> Option<&Kind> {
        self.items.iter().find(|item| item.hwnd == hwnd).map(|item| &item.kind)
    }

    fn update_save(&self) {
        if let Some(save) = self.item(&Kind::Save) {
            let enabled = self.changes().is_some();
            if (unsafe { IsWindowEnabled(save) } != 0) != enabled {
                unsafe { EnableWindow(save, enabled as i32) };
            }
        }
    }

    // the header, the banner and the panel; then what's in the panel
    fn layout(&mut self) {
        let (width, height) = client_size(self.hwnd);
        let header = self.s(HEADER);
        let icon = self.s(ICON_BUTTON);
        let icon_top = (header - icon) / 2;
        let mut right = width - self.s(MARGIN) + self.s(6);
        for item in &self.items {
            match item.kind {
                Kind::More => {
                    right -= icon;
                    unsafe { SetWindowPos(item.hwnd, ptr::null_mut(), right, icon_top, icon, icon, SWP_NOZORDER | SWP_NOACTIVATE) };
                }
                Kind::Back => unsafe {
                    SetWindowPos(item.hwnd, ptr::null_mut(), self.s(MARGIN) - self.s(8), icon_top, icon, icon, SWP_NOZORDER | SWP_NOACTIVATE);
                },
                _ => {}
            }
        }
        if let Some(add) = self.item(&Kind::Add) {
            let dc = unsafe { GetDC(self.hwnd) };
            let (text_width, _) = theme::measure(dc, &self.fonts, Font::Strong, strings::HOME_ADD, None);
            unsafe { ReleaseDC(self.hwnd, dc) };
            let button_width = text_width + self.s(16) + self.s(34);
            let button_height = self.s(34);
            let x = right - self.s(6) - button_width;
            unsafe { SetWindowPos(add, ptr::null_mut(), x, (header - button_height) / 2, button_width, button_height, SWP_NOZORDER | SWP_NOACTIVATE) };
        }
        let banner = if self.overview.service == ServiceState::Unavailable { self.s(BANNER) } else { 0 };
        if let Some(start) = self.item(&Kind::StartService) {
            let dc = unsafe { GetDC(self.hwnd) };
            let (text_width, _) = theme::measure(dc, &self.fonts, Font::Strong, strings::HOME_START_SERVICE, None);
            unsafe { ReleaseDC(self.hwnd, dc) };
            let (button_width, button_height) = (text_width + self.s(28), self.s(30));
            let x = width - self.s(MARGIN) - button_width;
            let y = header + (banner - button_height) / 2;
            unsafe { SetWindowPos(start, ptr::null_mut(), x, y, button_width, button_height, SWP_NOZORDER | SWP_NOACTIVATE) };
        }
        let top = header + banner;
        unsafe {
            SetWindowPos(self.panel, ptr::null_mut(), 0, top, width, (height - top).max(0), SWP_NOZORDER | SWP_NOACTIVATE);
            InvalidateRect(self.hwnd, ptr::null(), 0);
        }
        self.layout_panel();
    }

    fn layout_panel(&mut self) {
        // twice when the scroll bar comes or goes, which changes the width
        for _ in 0..2 {
            let (width, _) = client_size(self.panel);
            let dc = unsafe { GetDC(self.panel) };
            match &self.view {
                View::List => self.shape_list(dc, width),
                View::Vpn(_) => self.shape_page(dc, width),
            }
            unsafe { ReleaseDC(self.panel, dc) };
            self.set_scroll();
            if client_size(self.panel).0 == width {
                break;
            }
        }
        self.place_children();
        unsafe { InvalidateRect(self.panel, ptr::null(), 0) };
    }

    fn set_scroll(&mut self) {
        let (_, page) = client_size(self.panel);
        self.scroll = self.scroll.clamp(0, (self.content - page).max(0));
        let mut info: SCROLLINFO = unsafe { zeroed() };
        info.cbSize = size_of::<SCROLLINFO>() as u32;
        info.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        info.nMin = 0;
        info.nMax = (self.content - 1).max(0);
        info.nPage = page.max(0) as u32;
        info.nPos = self.scroll;
        unsafe { SetScrollInfo(self.panel, SB_VERT, &info, 1) };
    }

    fn place_children(&self) {
        for (hwnd, place) in &self.places {
            unsafe {
                SetWindowPos(
                    *hwnd,
                    ptr::null_mut(),
                    place.left,
                    place.top - self.scroll,
                    place.right - place.left,
                    place.bottom - place.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                )
            };
        }
    }

    fn scroll_to(&mut self, position: i32) {
        let (_, page) = client_size(self.panel);
        let position = position.clamp(0, (self.content - page).max(0));
        if position == self.scroll {
            return;
        }
        self.scroll = position;
        self.set_scroll();
        self.place_children();
        unsafe { RedrawWindow(self.panel, ptr::null(), ptr::null_mut(), RDW_INVALIDATE | RDW_ALLCHILDREN) };
    }

    fn on_scroll(&mut self, code: i32) {
        let (_, page) = client_size(self.panel);
        let target = match code {
            SB_LINEUP => self.scroll - self.s(SCROLL_LINE),
            SB_LINEDOWN => self.scroll + self.s(SCROLL_LINE),
            SB_PAGEUP => self.scroll - page,
            SB_PAGEDOWN => self.scroll + page,
            SB_TOP => 0,
            SB_BOTTOM => self.content,
            SB_THUMBTRACK => {
                let mut info: SCROLLINFO = unsafe { zeroed() };
                info.cbSize = size_of::<SCROLLINFO>() as u32;
                info.fMask = SIF_TRACKPOS;
                unsafe { GetScrollInfo(self.panel, SB_VERT, &mut info) };
                info.nTrackPos
            }
            _ => return,
        };
        self.scroll_to(target);
    }

    // a child that got the focus, into view
    fn reveal(&mut self, hwnd: HWND) {
        let Some((_, place)) = self.places.iter().find(|(child, _)| *child == hwnd) else { return };
        let (_, page) = client_size(self.panel);
        let margin = self.s(8);
        if place.top - margin < self.scroll {
            self.scroll_to(place.top - margin);
        } else if place.bottom + margin > self.scroll + page {
            self.scroll_to(place.bottom + margin - page);
        }
    }

    fn line(&self, dc: HDC, font: Font) -> i32 {
        theme::measure(dc, &self.fonts, font, "Xy", None).1
    }

    fn button_width(&self, dc: HDC, text: &str) -> i32 {
        (theme::measure(dc, &self.fonts, Font::Strong, text, None).0 + self.s(32)).max(self.s(88))
    }

    fn shape_list(&mut self, dc: HDC, width: i32) {
        let s = |value: i32| scale(value, self.dpi);
        let (left, right) = (s(MARGIN), width - s(MARGIN));
        let card_width = right - left;
        let pad = s(PAD);
        let (name_line, small_line, body_line) = (self.line(dc, Font::Name), self.line(dc, Font::Small), self.line(dc, Font::Body));
        let mut cards = Vec::new();
        let mut shapes = Vec::new();
        let mut places = Vec::new();
        let mut y = s(MARGIN);
        for card in &self.overview.cards {
            let switch_left = card_width - pad - s(14) - s(12) - s(SWITCH_WIDTH);
            let text_right = switch_left - s(12);
            let mut top = pad;
            let name_top = top;
            top += name_line + s(2);
            let sub_top = top;
            top += small_line + s(8);
            let state_top = top;
            top += body_line;
            let switch_top = (name_top + state_top + body_line) / 2 - s(SWITCH_HEIGHT) / 2;
            let traffic_top = card.traffic.as_ref().map(|_| {
                top += s(4);
                let at = top;
                top += small_line;
                at
            });
            let hint = card.hint.as_ref().map(|hint| {
                top += s(8);
                let (_, height) = theme::measure(dc, &self.fonts, Font::Small, hint, Some(card_width - pad * 2));
                let area = rect(pad, top, card_width - pad, top + height);
                top += height;
                area
            });
            let log_in = card.needs_login.then(|| {
                top += s(12);
                let area = rect(pad, top, pad + self.button_width(dc, strings::HOME_LOG_IN), top + s(BUTTON_HEIGHT));
                top += s(BUTTON_HEIGHT);
                area
            });
            top += pad;
            let place = rect(left, y, right, y + top);
            if let Some(hwnd) = self.item(&Kind::Card(card.name.clone())) {
                places.push((hwnd, place));
            }
            cards.push(CardShape {
                name: card.name.clone(),
                switch: rect(switch_left, switch_top, switch_left + s(SWITCH_WIDTH), switch_top + s(SWITCH_HEIGHT)),
                log_in,
                text_right,
                name_top,
                sub_top,
                state_top,
                traffic_top,
                hint,
            });
            y += top + s(GAP);
        }
        if let Some(hwnd) = self.item(&Kind::EmptyAdd) {
            // in the middle: a circle with the icon, a title, what to do and its button
            let circle = s(88);
            y = s(56);
            let center = width / 2;
            shapes.push(Shape::Circle { rect: rect(center - circle / 2, y, center + circle / 2, y + circle), color: self.palette.accent_soft });
            shapes.push(Shape::Text {
                rect: rect(center - circle / 2, y, center + circle / 2, y + circle),
                font: Font::IconLarge,
                color: self.palette.accent,
                text: theme::GLYPH_VPN.to_string(),
                format: DT_CENTER | DT_VCENTER | DT_SINGLELINE,
            });
            y += circle + s(20);
            let title = self.line(dc, Font::Title);
            shapes.push(Shape::Text {
                rect: rect(left, y, right, y + title),
                font: Font::Title,
                color: self.palette.text,
                text: strings::HOME_EMPTY_TITLE.to_string(),
                format: DT_CENTER | DT_SINGLELINE,
            });
            y += title + s(8);
            let text_width = (right - left).min(s(320));
            let (_, height) = theme::measure(dc, &self.fonts, Font::Body, strings::HOME_EMPTY_TEXT, Some(text_width));
            shapes.push(Shape::Text {
                rect: rect(center - text_width / 2, y, center + text_width / 2, y + height),
                font: Font::Body,
                color: self.palette.muted,
                text: strings::HOME_EMPTY_TEXT.to_string(),
                format: DT_CENTER | DT_WORDBREAK,
            });
            y += height + s(20);
            let button_width = self.button_width(dc, strings::HOME_EMPTY_ADD) + s(16);
            let button_height = s(BUTTON_HEIGHT + 6);
            places.push((hwnd, rect(center - button_width / 2, y, center + button_width / 2, y + button_height)));
            y += button_height + s(MARGIN) + s(GAP);
        }
        self.content = y - s(GAP) + s(MARGIN) / 2;
        self.cards = cards;
        self.shapes = shapes;
        self.places = places;
    }

    fn text_shape(&self, rect: RECT, font: Font, color: u32, text: impl Into<String>, format: u32) -> Shape {
        Shape::Text { rect, font, color, text: text.into(), format }
    }

    fn shape_page(&mut self, dc: HDC, width: i32) {
        let s = |value: i32| scale(value, self.dpi);
        let Some(card) = self.card().cloned() else {
            self.shapes.clear();
            self.places.clear();
            self.content = 0;
            return;
        };
        let palette = self.palette;
        let (left, right) = (s(MARGIN), width - s(MARGIN));
        let pad = s(PAD);
        let (inner_left, inner_right) = (left + pad, right - pad);
        let (name_line, small_line, body_line, strong_line, value_line) = (
            self.line(dc, Font::Name),
            self.line(dc, Font::Small),
            self.line(dc, Font::Body),
            self.line(dc, Font::Strong),
            self.line(dc, Font::Value),
        );
        let mut shapes = Vec::new();
        let mut places = Vec::new();
        let ellipsis = DT_SINGLELINE | DT_END_ELLIPSIS | DT_LEFT;
        let mut y = s(MARGIN);

        // the state, the switch and the login
        let top = y;
        y += pad;
        let switch = (s(SWITCH_WIDTH + 8), s(SWITCH_HEIGHT + 8));
        let switch_left = inner_right - switch.0 + s(4);
        if let Some(hwnd) = self.item(&Kind::Switch) {
            places.push((hwnd, rect(switch_left, y + (name_line - switch.1) / 2, switch_left + switch.0, y + (name_line + switch.1) / 2)));
        }
        let dot = s(5);
        shapes.push(Shape::Dot { x: inner_left + dot, y: y + name_line / 2, radius: dot, color: self.tone_color(card.tone) });
        let state_color = self.state_color(card.tone);
        shapes.push(self.text_shape(rect(inner_left + dot * 2 + s(10), y, switch_left - s(12), y + name_line), Font::Name, state_color, card.state.clone(), ellipsis));
        y += name_line + s(4);
        let sub = card.subtitle();
        if !sub.is_empty() {
            shapes.push(self.text_shape(rect(inner_left, y, switch_left - s(12), y + small_line), Font::Small, palette.muted, sub, ellipsis));
            y += small_line;
        }
        if let Some(hint) = &card.hint {
            y += s(10);
            let (_, height) = theme::measure(dc, &self.fonts, Font::Small, hint, Some(inner_right - inner_left));
            shapes.push(self.text_shape(rect(inner_left, y, inner_right, y + height), Font::Small, state_color, hint.clone(), DT_WORDBREAK));
            y += height;
        }
        if let Some(hwnd) = self.item(&Kind::LogIn) {
            y += s(14);
            places.push((hwnd, rect(inner_left, y, inner_left + self.button_width(dc, strings::HOME_LOG_IN), y + s(BUTTON_HEIGHT))));
            y += s(BUTTON_HEIGHT);
        }
        y += pad;
        shapes.insert(0, Shape::Panel(rect(left, top, right, y)));
        y += s(GAP);

        // the traffic
        let top = y;
        let at = shapes.len();
        y += pad;
        shapes.push(self.text_shape(rect(inner_left, y, inner_right, y + strong_line), Font::Strong, palette.text, strings::HOME_TRAFFIC, ellipsis));
        y += strong_line + s(12);
        let column = inner_left + (inner_right - inner_left) / 2 + s(6);
        let pair = |shapes: &mut Vec<Shape>, y: &mut i32, cells: [(&str, String); 2]| {
            for (index, (label, value)) in cells.into_iter().enumerate() {
                let (x, end) = if index == 0 { (inner_left, column - s(12)) } else { (column, inner_right) };
                shapes.push(Shape::Text { rect: rect(x, *y, end, *y + small_line), font: Font::Small, color: palette.muted, text: label.to_string(), format: ellipsis });
                let value_top = *y + small_line + s(2);
                shapes.push(Shape::Text { rect: rect(x, value_top, end, value_top + strong_line), font: Font::Strong, color: palette.text, text: value, format: ellipsis });
            }
            *y += small_line + s(2) + strong_line + s(14);
        };
        match &card.traffic {
            Some(traffic) => {
                shapes.push(Shape::Graph(rect(inner_left, y, inner_right, y + s(GRAPH_HEIGHT))));
                y += s(GRAPH_HEIGHT) + s(12);
                let (down, up) = self.history.get(&card.name).map(History::now).unwrap_or((0.0, 0.0));
                for (index, (label, rate, color)) in
                    [(strings::HOME_DOWNLOAD, down, palette.accent), (strings::HOME_UPLOAD, up, palette.upload)].into_iter().enumerate()
                {
                    let x = if index == 0 { inner_left } else { column };
                    shapes.push(Shape::Dot { x: x + s(4), y: y + small_line / 2, radius: s(4), color });
                    shapes.push(Shape::Text { rect: rect(x + s(14), y, x + s(200), y + small_line), font: Font::Small, color: palette.muted, text: label.to_string(), format: ellipsis });
                    let value_top = y + small_line + s(2);
                    shapes.push(Shape::Text { rect: rect(x, value_top, x + s(200), value_top + value_line), font: Font::Value, color: palette.text, text: strings::value_rate(rate), format: ellipsis });
                }
                y += small_line + s(2) + value_line + s(16);
                pair(&mut shapes, &mut y, self.duration_cells(traffic));
                pair(&mut shapes, &mut y, [
                    (strings::DETAIL_RECEIVED, strings::value_bytes(traffic.rx_bytes)),
                    (strings::DETAIL_SENT, strings::value_bytes(traffic.tx_bytes)),
                ]);
                pair(&mut shapes, &mut y, [
                    (strings::HOME_ADDRESS, if traffic.address.is_empty() { strings::VALUE_NONE.to_string() } else { traffic.address.clone() }),
                    (strings::HOME_SERVER, if traffic.server.is_empty() { card.host.clone() } else { traffic.server.clone() }),
                ]);
            }
            None => {
                let (_, height) = theme::measure(dc, &self.fonts, Font::Body, strings::HOME_TRAFFIC_OFF, Some(inner_right - inner_left));
                shapes.push(self.text_shape(rect(inner_left, y, inner_right, y + height), Font::Body, palette.muted, strings::HOME_TRAFFIC_OFF, DT_WORDBREAK));
                y += height + s(14);
            }
        }
        shapes.push(self.text_shape(rect(inner_left, y, inner_right, y + small_line), Font::Small, palette.muted, strings::HOME_ROUTING, ellipsis));
        y += small_line + s(2);
        let (_, height) = theme::measure(dc, &self.fonts, Font::Body, &card.routing, Some(inner_right - inner_left));
        shapes.push(self.text_shape(rect(inner_left, y, inner_right, y + height), Font::Body, palette.text, card.routing.clone(), DT_WORDBREAK));
        y += height + pad;
        shapes.insert(at, Shape::Panel(rect(left, top, right, y)));
        y += s(GAP);

        // the settings: the name, the login
        let top = y;
        let at = shapes.len();
        y += pad;
        shapes.push(self.text_shape(rect(inner_left, y, inner_right, y + strong_line), Font::Strong, palette.text, strings::HOME_SETTINGS, ellipsis));
        y += strong_line + s(14);
        let edit_line = body_line;
        let field = |shapes: &mut Vec<Shape>, places: &mut Vec<(HWND, RECT)>, y: &mut i32, label: &str, edit: HWND| {
            shapes.push(Shape::Text { rect: rect(inner_left, *y, inner_right, *y + small_line), font: Font::Small, color: palette.muted, text: label.to_string(), format: ellipsis });
            *y += small_line + s(6);
            let frame = rect(inner_left, *y, inner_right, *y + s(FIELD_HEIGHT));
            shapes.push(Shape::Field(frame, edit));
            let top = frame.top + (s(FIELD_HEIGHT) - edit_line) / 2;
            places.push((edit, rect(frame.left + s(10), top, frame.right - s(10), top + edit_line)));
            *y += s(FIELD_HEIGHT);
        };
        let (name_edit, user_edit, saved_password, saved_user, locked) = match &self.page {
            Some(page) => (page.name_edit, page.user_edit, page.saved_password, page.saved_user.clone(), page.name_locked),
            None => (ptr::null_mut(), ptr::null_mut(), false, String::new(), false),
        };
        if !name_edit.is_null() {
            field(&mut shapes, &mut places, &mut y, strings::HOME_NAME, name_edit);
            if locked {
                y += s(6);
                shapes.push(self.text_shape(rect(inner_left, y, inner_right, y + small_line), Font::Small, palette.muted, strings::HOME_RENAME_OFF, ellipsis));
                y += small_line;
            }
            y += s(16);
        }
        if !user_edit.is_null() {
            field(&mut shapes, &mut places, &mut y, strings::HOME_USERNAME, user_edit);
            y += s(10);
            let text = if saved_password { strings::HOME_PASSWORD_SAVED } else { strings::HOME_PASSWORD_NOT_SAVED };
            let mut text_right = inner_right;
            if let Some(hwnd) = self.item(&Kind::Forget) {
                let button_width = theme::measure(dc, &self.fonts, Font::Strong, strings::HOME_FORGET, None).0 + s(20);
                let button_height = small_line + s(10);
                places.push((hwnd, rect(inner_right - button_width + s(8), y - s(5), inner_right + s(8), y - s(5) + button_height)));
                text_right = inner_right - button_width - s(4);
            }
            let (_, height) = theme::measure(dc, &self.fonts, Font::Small, text, Some(text_right - inner_left));
            shapes.push(self.text_shape(rect(inner_left, y, text_right, y + height), Font::Small, palette.muted, text, DT_WORDBREAK));
            y += height;
            if saved_password && get_text(user_edit).trim() != saved_user {
                y += s(6);
                let note = strings::home_username_changed(&saved_user);
                let (_, height) = theme::measure(dc, &self.fonts, Font::Small, &note, Some(inner_right - inner_left));
                shapes.push(self.text_shape(rect(inner_left, y, inner_right, y + height), Font::Small, palette.warning, note, DT_WORDBREAK));
                y += height;
            }
            y += s(16);
        } else {
            let (_, height) = theme::measure(dc, &self.fonts, Font::Small, strings::HOME_NO_LOGIN, Some(inner_right - inner_left));
            shapes.push(self.text_shape(rect(inner_left, y, inner_right, y + height), Font::Small, palette.muted, strings::HOME_NO_LOGIN, DT_WORDBREAK));
            y += height + s(16);
        }
        if let Some(hwnd) = self.item(&Kind::Save) {
            let button_width = self.button_width(dc, strings::HOME_SAVE);
            places.push((hwnd, rect(inner_right - button_width, y, inner_right, y + s(BUTTON_HEIGHT))));
            y += s(BUTTON_HEIGHT);
        }
        y += pad;
        shapes.insert(at, Shape::Panel(rect(left, top, right, y)));
        y += s(GAP) + s(4);

        // all the details, and the removal
        let mut x = left;
        for kind in [Kind::Details, Kind::Remove] {
            if let Some(hwnd) = self.item(&kind) {
                let button_width = self.button_width(dc, &self.label(&kind));
                places.push((hwnd, rect(x, y, x + button_width, y + s(BUTTON_HEIGHT))));
                x += button_width + s(10);
            }
        }
        y += s(BUTTON_HEIGHT) + s(MARGIN);
        self.content = y;
        self.shapes = shapes;
        self.places = places;
    }

    fn duration_cells(&self, traffic: &Traffic) -> [(&'static str, String); 2] {
        let duration = if traffic.since == 0 { strings::VALUE_NOT_YET.to_string() } else { strings::value_duration(unix_now().saturating_sub(traffic.since)) };
        [(strings::HOME_DURATION, duration), (strings::DETAIL_HANDSHAKE, handshake_text(traffic.handshake))]
    }

    fn tone_color(&self, tone: Tone) -> u32 {
        match tone {
            Tone::Off => self.palette.off,
            Tone::Busy => self.palette.accent,
            Tone::Good => self.palette.good,
            Tone::Warning => self.palette.warning,
            Tone::Bad => self.palette.bad,
        }
    }

    fn state_color(&self, tone: Tone) -> u32 {
        match tone {
            Tone::Warning => self.palette.warning,
            Tone::Bad => self.palette.bad,
            _ => self.palette.text,
        }
    }

    // the views

    fn show_list(&mut self) {
        // back to the card of the page, where the list was: the focus on the first one would scroll up to it
        let left = match &self.view {
            View::Vpn(name) => Some(Kind::Card(name.clone())),
            View::List => None,
        };
        self.close_page();
        self.view = View::List;
        self.scroll = self.list_scroll;
        self.sync();
        self.layout();
        let first = self.items.iter().find(|item| matches!(item.kind, Kind::Card(_) | Kind::EmptyAdd)).map(|item| item.hwnd);
        if let Some(focus) = left.and_then(|kind| self.item(&kind)).or(first) {
            unsafe { SetFocus(focus) };
        }
    }

    fn show_page(&mut self, name: &str) {
        let Some(card) = self.overview.card(name).cloned() else { return };
        if self.view == View::List {
            self.list_scroll = self.scroll;
        }
        self.close_page();
        let edit = WS_TABSTOP | ES_AUTOHSCROLL as u32;
        let name_edit = child(self.panel, "EDIT", &card.name, edit, 0, 0);
        set_font(name_edit, self.fonts.get(Font::Body));
        unsafe { SendMessageW(name_edit, EM_SETLIMITTEXT, MAX_NAME_LENGTH, 0) };
        let saved = card.page.as_ref().map(creds::read);
        let user_edit = match &saved {
            Some(saved) => {
                let hwnd = child(self.panel, "EDIT", &saved.username, edit, 0, 0);
                set_font(hwnd, self.fonts.get(Font::Body));
                hwnd
            }
            None => ptr::null_mut(),
        };
        self.page = Some(VpnPage {
            name: card.name.clone(),
            name_edit,
            user_edit,
            login: card.page,
            saved_user: saved.as_ref().map(|saved| saved.username.clone()).unwrap_or_default(),
            saved_password: saved.as_ref().is_some_and(|saved| saved.password.is_some()),
            name_locked: false,
        });
        self.view = View::Vpn(card.name.clone());
        self.scroll = 0;
        self.sync();
        self.layout();
        if let Some(switch) = self.item(&Kind::Switch) {
            unsafe { SetFocus(switch) };
        }
    }

    fn close_page(&mut self) {
        if let Some(page) = self.page.take() {
            for edit in [page.name_edit, page.user_edit] {
                if !edit.is_null() {
                    unsafe { DestroyWindow(edit) };
                }
            }
        }
    }

    // after a rename done on the page
    fn page_renamed(&mut self, new_name: &str) {
        if let Some(page) = self.page.as_mut() {
            page.name = new_name.to_string();
        }
        self.view = View::Vpn(new_name.to_string());
        self.history.clear();
    }

    // the saved login again, after a change
    fn reload_login(&mut self) {
        if let Some(page) = self.page.as_mut() {
            if let Some(login) = &page.login {
                let saved = creds::read(login);
                page.saved_password = saved.password.is_some();
                page.saved_user = saved.username;
            }
        }
        self.sync();
        self.layout();
    }

    fn changes(&self) -> Option<Changes> {
        let page = self.page.as_ref()?;
        let new_name = get_text(page.name_edit).trim().to_string();
        let username = match (&page.login, page.user_edit.is_null()) {
            (Some(login), false) => Some((*login, get_text(page.user_edit).trim().to_string())),
            _ => None,
        };
        let changes = Changes {
            name: page.name.clone(),
            new_name: (new_name != page.name).then_some(new_name),
            username: username.filter(|(_, username)| *username != page.saved_user),
        };
        (changes.new_name.is_some() || changes.username.is_some()).then_some(changes)
    }

    // the login of the page as saved: for "Forget it"
    fn saved_login(&self) -> Option<(LoginPage, String)> {
        let page = self.page.as_ref()?;
        Some((page.login?, page.saved_user.clone()))
    }

    // What a click on a button does; on a card, where it was
    fn action(&self, hwnd: HWND, click: Option<POINT>) -> Option<Action> {
        let kind = self.kind_of(hwnd)?.clone();
        let page_card = || self.card();
        Some(match kind {
            Kind::More => Action::More(hwnd),
            Kind::Back => Action::Back,
            Kind::Add | Kind::EmptyAdd => Action::Add,
            Kind::StartService => Action::StartService,
            Kind::Card(name) => {
                let card = self.overview.card(&name)?;
                match click.map_or(Part::Body, |point| self.part_at(&name, point)) {
                    Part::Switch if card.can_switch => Action::Toggle(name, card.on),
                    Part::Switch => return None,
                    Part::LogIn => Action::LogIn(name),
                    _ => Action::Open(name),
                }
            }
            Kind::Switch => {
                let card = page_card()?;
                if !card.can_switch {
                    return None;
                }
                Action::Toggle(card.name.clone(), card.on)
            }
            Kind::LogIn => Action::LogIn(page_card()?.name.clone()),
            Kind::Forget => Action::Forget,
            Kind::Save => Action::Save,
            Kind::Details => Action::Details(page_card()?.name.clone()),
            Kind::Remove => Action::Remove(page_card()?.name.clone()),
        })
    }

    fn shape_of(&self, name: &str) -> Option<&CardShape> {
        self.cards.iter().find(|shape| shape.name == name)
    }

    fn part_at(&self, name: &str, point: POINT) -> Part {
        let Some(shape) = self.shape_of(name) else { return Part::Nothing };
        // a bit around the switch, for the fingers
        let around = self.s(8);
        if contains(&inset(&shape.switch, -around), point) {
            return Part::Switch;
        }
        if shape.log_in.as_ref().is_some_and(|area| contains(area, point)) {
            return Part::LogIn;
        }
        Part::Body
    }

    // the mouse moved on a button: a card draws again when it goes to another part of it
    fn hovered(&self, hwnd: HWND) {
        let (hot, point) = HOT.get();
        let part = match self.kind_of(hwnd) {
            Some(Kind::Card(name)) if hot == hwnd => self.part_at(name, point),
            _ => Part::Nothing,
        };
        if HOT_PART.get() != (hwnd, part) {
            HOT_PART.set((hwnd, part));
            unsafe { InvalidateRect(hwnd, ptr::null(), 0) };
        }
    }

    fn dpi_changed(&mut self, dpi: u32, suggested: &RECT) {
        self.dpi = dpi;
        let previous = replace(&mut self.fonts, Fonts::new(dpi));
        if let Some(page) = &self.page {
            for edit in [page.name_edit, page.user_edit] {
                if !edit.is_null() {
                    set_font(edit, self.fonts.get(Font::Body));
                }
            }
        }
        drop(previous);
        unsafe { DestroyIcon(self.icon) };
        self.icon = load_icon(dpi);
        unsafe {
            SetWindowPos(
                self.hwnd,
                ptr::null_mut(),
                suggested.left,
                suggested.top,
                suggested.right - suggested.left,
                suggested.bottom - suggested.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
        };
        self.layout();
    }

    // the colors of the system changed: high contrast on or off
    fn colors_changed(&mut self) {
        self.palette = Palette::system();
        unsafe {
            DeleteObject(self.surface_brush as HGDIOBJ);
            DeleteObject(self.background_brush as HGDIOBJ);
        }
        self.surface_brush = theme::brush(self.palette.surface);
        self.background_brush = theme::brush(self.palette.background);
        self.layout();
        unsafe { RedrawWindow(self.hwnd, ptr::null(), ptr::null_mut(), RDW_INVALIDATE | RDW_ALLCHILDREN) };
    }

    // painting

    fn paint_header(&self, dc: HDC, width: i32, height: i32) {
        let palette = &self.palette;
        let header = self.s(HEADER);
        theme::fill(dc, &rect(0, 0, width, height), palette.background);
        theme::fill(dc, &rect(0, 0, width, header), palette.surface);
        theme::fill(dc, &rect(0, header - 1, width, header), palette.border);
        let title_line = theme::measure(dc, &self.fonts, Font::Title, "Xy", None).1;
        let title_top = (header - title_line) / 2;
        match &self.view {
            View::List => {
                let size = self.s(24);
                unsafe { DrawIconEx(dc, self.s(MARGIN), (header - size) / 2, self.icon, size, size, 0, ptr::null_mut(), DI_NORMAL) };
                let left = self.s(MARGIN) + size + self.s(10);
                let right = self.item(&Kind::Add).map_or(width, |add| self.left_of(add) - self.s(8));
                theme::text(dc, &self.fonts, Font::Title, palette.text, PRODUCT, &rect(left, title_top, right, title_top + title_line), DT_SINGLELINE | DT_END_ELLIPSIS);
            }
            View::Vpn(name) => {
                let left = self.s(MARGIN) - self.s(8) + self.s(ICON_BUTTON) + self.s(6);
                let right = self.item(&Kind::More).map_or(width, |more| self.left_of(more) - self.s(8));
                theme::text(dc, &self.fonts, Font::Title, palette.text, name, &rect(left, title_top, right, title_top + title_line), DT_SINGLELINE | DT_END_ELLIPSIS);
            }
        }
        if self.overview.service == ServiceState::Unavailable {
            let banner = rect(0, header, width, header + self.s(BANNER));
            theme::fill(dc, &banner, palette.banner);
            let icon = rect(self.s(MARGIN), banner.top, self.s(MARGIN) + self.s(20), banner.bottom);
            theme::text(dc, &self.fonts, Font::Icon, palette.warning, &theme::GLYPH_WARNING.to_string(), &icon, DT_SINGLELINE | DT_VCENTER | DT_LEFT);
            let right = self.item(&Kind::StartService).map_or(width, |start| self.left_of(start) - self.s(10));
            let text = rect(icon.right + self.s(8), banner.top, right, banner.bottom);
            theme::text(dc, &self.fonts, Font::Body, palette.text, strings::MENU_SERVICE_DOWN, &text, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        }
    }

    // where a child of the main window starts, in its client area
    fn left_of(&self, hwnd: HWND) -> i32 {
        let mut window: RECT = unsafe { zeroed() };
        unsafe { GetWindowRect(hwnd, &mut window) };
        let mut place = POINT { x: window.left, y: window.top };
        unsafe { windows_sys::Win32::Graphics::Gdi::ScreenToClient(self.hwnd, &mut place) };
        place.x
    }

    fn paint_panel(&self, dc: HDC, width: i32, height: i32) {
        theme::fill(dc, &rect(0, 0, width, height), self.palette.background);
        let dy = -self.scroll;
        let focus = unsafe { GetFocus() };
        {
            let canvas = Canvas::new(dc);
            for shape in &self.shapes {
                match shape {
                    Shape::Panel(area) => {
                        let area = shifted(area, 0, dy);
                        canvas.fill_round(&area, self.s(RADIUS) as f32, self.palette.surface);
                        canvas.stroke_round(&area, self.s(RADIUS) as f32, 1.0, self.palette.border);
                    }
                    Shape::Dot { x, y, radius, color } => canvas.fill_circle(*x as f32, (*y + dy) as f32, *radius as f32, *color),
                    Shape::Circle { rect: area, color } => {
                        let area = shifted(area, 0, dy);
                        let radius = (area.right - area.left) as f32 / 2.0;
                        canvas.fill_circle(area.left as f32 + radius, area.top as f32 + radius, radius, *color);
                    }
                    Shape::Graph(area) => self.paint_graph(&canvas, &shifted(area, 0, dy)),
                    Shape::Field(area, edit) => {
                        let area = shifted(area, 0, dy);
                        let locked = self.page.as_ref().is_some_and(|page| page.name_locked && page.name_edit == *edit);
                        let fill = if locked { self.palette.background } else { self.palette.surface };
                        canvas.fill_round(&area, self.s(6) as f32, fill);
                        if focus == *edit && !locked {
                            canvas.stroke_round(&area, self.s(6) as f32, 2.0, self.palette.accent);
                        } else {
                            canvas.stroke_round(&area, self.s(6) as f32, 1.0, self.palette.border);
                        }
                    }
                    Shape::Text { .. } => {}
                }
            }
        }
        for shape in &self.shapes {
            match shape {
                Shape::Text { rect: area, font, color, text, format } => {
                    theme::text(dc, &self.fonts, *font, *color, text, &shifted(area, 0, dy), *format);
                }
                Shape::Graph(area) => self.paint_graph_scale(dc, &shifted(area, 0, dy)),
                _ => {}
            }
        }
    }

    fn graph_top(&self) -> f64 {
        let View::Vpn(name) = &self.view else { return 1024.0 };
        self.history.get(name).map_or(1024.0, History::top)
    }

    // received in the accent, filled under; sent in teal; the newest on the right
    fn paint_graph(&self, canvas: &Canvas, area: &RECT) {
        canvas.fill_round(area, self.s(6) as f32, mix(self.palette.background, self.palette.surface, 0.4));
        let View::Vpn(name) = &self.view else { return };
        let Some(history) = self.history.get(name) else { return };
        let top = self.graph_top();
        let (left, right) = (area.left as f32 + 2.0, area.right as f32 - 2.0);
        let (upper, bottom) = (area.top as f32 + self.s(18) as f32, area.bottom as f32 - 2.0);
        let step = (right - left) / (SAMPLES - 1) as f32;
        let count = history.rates.len();
        let line = |value: fn(&(f64, f64)) -> f64| -> Vec<_> {
            history
                .rates
                .iter()
                .enumerate()
                .map(|(index, rate)| {
                    let x = right - (count - 1 - index) as f32 * step;
                    let y = bottom - ((value(rate) / top) as f32).min(1.0) * (bottom - upper);
                    point(x, y)
                })
                .collect()
        };
        let received = line(|rate| rate.0);
        let sent = line(|rate| rate.1);
        if let (Some(first), Some(last)) = (received.first(), received.last()) {
            let mut area_points = received.clone();
            area_points.push(point(last.X, bottom));
            area_points.push(point(first.X, bottom));
            canvas.fill_polygon(&area_points, self.palette.accent, 40);
        }
        canvas.lines(&received, 2.0, self.palette.accent);
        canvas.lines(&sent, 2.0, self.palette.upload);
    }

    // the speed at the top of the graph
    fn paint_graph_scale(&self, dc: HDC, area: &RECT) {
        let label = rect(area.left + self.s(8), area.top + self.s(3), area.right - self.s(8), area.top + self.s(18));
        theme::text(dc, &self.fonts, Font::Small, self.palette.muted, &strings::value_rate(self.graph_top()), &label, DT_SINGLELINE | DT_RIGHT);
    }

    fn draw_item(&self, item: &DRAWITEMSTRUCT) {
        let Some(kind) = self.kind_of(item.hwndItem) else { return };
        let (width, height) = (item.rcItem.right - item.rcItem.left, item.rcItem.bottom - item.rcItem.top);
        let buffer = Buffer::new(item.hDC, width, height);
        let dc = buffer.dc();
        let area = rect(0, 0, width, height);
        let state = item.itemState;
        let focused = state & ODS_FOCUS != 0 && state & ODS_NOFOCUSRECT == 0;
        let pressed = state & ODS_SELECTED != 0;
        let disabled = state & ODS_DISABLED != 0;
        let hot = HOT.get().0 == item.hwndItem && !disabled;
        let palette = self.palette;
        match kind {
            Kind::More | Kind::Back => {
                theme::fill(dc, &area, palette.surface);
                {
                    let canvas = Canvas::new(dc);
                    if hot || pressed {
                        canvas.fill_round(&area, (height / 2) as f32, if pressed { palette.border } else { palette.background });
                    }
                    if focused {
                        canvas.stroke_round(&area, (height / 2) as f32, 2.0, palette.accent);
                    }
                }
                let glyph = if *kind == Kind::More { theme::GLYPH_MORE } else { theme::GLYPH_BACK };
                theme::text(dc, &self.fonts, Font::Icon, palette.text, &glyph.to_string(), &area, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            }
            Kind::Add | Kind::EmptyAdd => {
                let backdrop = if *kind == Kind::Add { palette.surface } else { palette.background };
                self.draw_button(dc, &area, &self.label(kind), Style::Primary, backdrop, hot, pressed, focused, disabled, Some(theme::GLYPH_ADD));
            }
            Kind::StartService => {
                self.draw_button(dc, &area, strings::HOME_START_SERVICE, Style::Caution, palette.banner, hot, pressed, focused, disabled, None)
            }
            Kind::Card(name) => {
                if let (Some(card), Some(shape)) = (self.overview.card(name), self.shape_of(name)) {
                    self.draw_card(dc, &area, card, shape, item.hwndItem, focused);
                }
            }
            Kind::Switch => {
                theme::fill(dc, &area, palette.surface);
                if let Some(card) = self.card() {
                    let canvas = Canvas::new(dc);
                    let track = inset(&area, self.s(4));
                    self.draw_switch(&canvas, &track, card, hot);
                    if focused {
                        canvas.stroke_round(&area, (height / 2) as f32, 2.0, palette.accent);
                    }
                }
            }
            Kind::LogIn => self.draw_button(dc, &area, strings::HOME_LOG_IN, Style::Primary, palette.surface, hot, pressed, focused, disabled, None),
            Kind::Forget => self.draw_button(dc, &area, strings::HOME_FORGET, Style::Link, palette.surface, hot, pressed, focused, disabled, None),
            Kind::Save => self.draw_button(dc, &area, strings::HOME_SAVE, Style::Primary, palette.surface, hot, pressed, focused, disabled, None),
            Kind::Details => {
                self.draw_button(dc, &area, strings::HOME_ALL_DETAILS, Style::Secondary, palette.background, hot, pressed, focused, disabled, None)
            }
            Kind::Remove => self.draw_button(dc, &area, strings::HOME_REMOVE, Style::Danger, palette.background, hot, pressed, focused, disabled, None),
        }
        drop(buffer);
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_button(
        &self,
        dc: HDC,
        area: &RECT,
        text: &str,
        style: Style,
        backdrop: u32,
        hot: bool,
        pressed: bool,
        focused: bool,
        disabled: bool,
        glyph: Option<char>,
    ) {
        let palette = &self.palette;
        let radius = self.s(BUTTON_RADIUS) as f32;
        theme::fill(dc, area, backdrop);
        let (fill, line, color) = match style {
            _ if disabled => (Some(palette.track), None, palette.surface),
            Style::Primary => (Some(if hot || pressed { palette.accent_hover } else { palette.accent }), None, palette.on_accent),
            Style::Secondary => (Some(if hot || pressed { palette.hover } else { palette.surface }), Some(palette.border), palette.text),
            Style::Danger => (Some(if hot || pressed { rgb(0xfe, 0xf2, 0xf2) } else { palette.surface }), Some(palette.bad), palette.bad),
            Style::Caution => (Some(palette.surface), Some(palette.warning), palette.warning),
            Style::Link => ((hot || pressed).then_some(palette.accent_soft), None, palette.accent),
        };
        {
            let canvas = Canvas::new(dc);
            if let Some(fill) = fill {
                canvas.fill_round(area, radius, fill);
            }
            if let Some(line) = line {
                canvas.stroke_round(area, radius, 1.0, line);
            }
            if focused {
                if style == Style::Primary && !disabled {
                    canvas.stroke_round(&inset(area, 2), radius - 2.0, 1.5, palette.on_accent);
                } else {
                    canvas.stroke_round(area, radius, 2.0, palette.accent);
                }
            }
        }
        let format = DT_SINGLELINE | DT_VCENTER;
        match glyph {
            Some(glyph) => {
                let (text_width, _) = theme::measure(dc, &self.fonts, Font::Strong, text, None);
                let icon = self.s(16);
                let gap = self.s(8);
                let start = area.left + ((area.right - area.left) - text_width - icon - gap) / 2;
                theme::text(dc, &self.fonts, Font::Icon, color, &glyph.to_string(), &rect(start, area.top, start + icon, area.bottom), format | DT_CENTER);
                theme::text(dc, &self.fonts, Font::Strong, color, text, &rect(start + icon + gap, area.top, area.right, area.bottom), format | DT_LEFT);
            }
            None => {
                theme::text(dc, &self.fonts, Font::Strong, color, text, area, format | DT_CENTER);
            }
        }
    }

    fn draw_switch(&self, canvas: &Canvas, track: &RECT, card: &Card, hot: bool) {
        let palette = &self.palette;
        let height = (track.bottom - track.top) as f32;
        let busy = card.tone == Tone::Busy;
        let color = match (card.on, card.can_switch) {
            (_, false) => palette.track,
            (true, _) if busy => mix(palette.accent, palette.surface, 0.45),
            (true, _) if hot => palette.accent_hover,
            (true, _) => palette.accent,
            (false, _) if hot => palette.off,
            (false, _) => palette.track,
        };
        canvas.fill_round(track, height / 2.0, color);
        let radius = height / 2.0 - self.s(3) as f32;
        let center_y = track.top as f32 + height / 2.0;
        let center_x = if card.on { track.right as f32 - height / 2.0 } else { track.left as f32 + height / 2.0 };
        canvas.fill_circle(center_x, center_y, radius, palette.surface);
    }

    fn draw_card(&self, dc: HDC, area: &RECT, card: &Card, shape: &CardShape, hwnd: HWND, focused: bool) {
        let palette = &self.palette;
        let s = |value: i32| self.s(value);
        let (hot, part) = HOT_PART.get();
        let part = if hot == hwnd && HOT.get().0 == hwnd { part } else { Part::Nothing };
        theme::fill(dc, area, palette.background);
        let radius = s(RADIUS) as f32;
        let pad = s(PAD);
        {
            let canvas = Canvas::new(dc);
            canvas.fill_round(area, radius, if part == Part::Body { palette.hover } else { palette.surface });
            let line = if part != Part::Nothing { mix(palette.border, palette.accent, 0.5) } else { palette.border };
            canvas.stroke_round(area, radius, 1.0, line);
            if focused {
                canvas.stroke_round(area, radius, 2.0, palette.accent);
            }
            let body_line = theme::measure(dc, &self.fonts, Font::Body, "Xy", None).1;
            canvas.fill_circle((pad + s(4)) as f32, (shape.state_top + body_line / 2) as f32, s(4) as f32, self.tone_color(card.tone));
            self.draw_switch(&canvas, &shape.switch, card, part == Part::Switch);
            if let Some(log_in) = &shape.log_in {
                let fill = if part == Part::LogIn { palette.accent_hover } else { palette.accent };
                canvas.fill_round(log_in, s(BUTTON_RADIUS) as f32, fill);
            }
        }
        let ellipsis = DT_SINGLELINE | DT_END_ELLIPSIS | DT_LEFT;
        let text_right = shape.text_right;
        let line = |font: Font| theme::measure(dc, &self.fonts, font, "Xy", None).1;
        theme::text(dc, &self.fonts, Font::Name, palette.text, &card.name, &rect(pad, shape.name_top, text_right, shape.name_top + line(Font::Name)), ellipsis);
        theme::text(dc, &self.fonts, Font::Small, palette.muted, &card.subtitle(), &rect(pad, shape.sub_top, text_right, shape.sub_top + line(Font::Small)), ellipsis);
        let state = rect(pad + s(16), shape.state_top, text_right, shape.state_top + line(Font::Body));
        theme::text(dc, &self.fonts, Font::Body, self.state_color(card.tone), &card.state, &state, ellipsis);
        if let (Some(top), Some(traffic)) = (shape.traffic_top, &card.traffic) {
            let (down, up) = self.history.get(&card.name).map(History::now).unwrap_or((0.0, 0.0));
            let duration = if traffic.since == 0 { String::new() } else { strings::value_duration(unix_now().saturating_sub(traffic.since)) };
            let text = format!("\u{2193} {}    \u{2191} {}    {}", strings::value_rate(down), strings::value_rate(up), duration);
            theme::text(dc, &self.fonts, Font::Small, palette.muted, &text, &rect(pad, top, text_right, top + line(Font::Small)), ellipsis);
        }
        if let (Some(hint), Some(text)) = (&shape.hint, &card.hint) {
            theme::text(dc, &self.fonts, Font::Small, self.state_color(card.tone), text, hint, DT_WORDBREAK);
        }
        if let Some(log_in) = &shape.log_in {
            theme::text(dc, &self.fonts, Font::Strong, palette.on_accent, strings::HOME_LOG_IN, log_in, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
        }
        let chevron = rect(area.right - pad - s(14), shape.switch.top, area.right - pad, shape.switch.bottom);
        theme::text(dc, &self.fonts, Font::Icon, palette.muted, &theme::GLYPH_CHEVRON.to_string(), &chevron, DT_SINGLELINE | DT_VCENTER | DT_RIGHT);
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        self.save_place();
        remove_dialog(self.hwnd);
        unsafe {
            DestroyWindow(self.hwnd);
            DeleteObject(self.surface_brush as HGDIOBJ);
            DeleteObject(self.background_brush as HGDIOBJ);
            DestroyIcon(self.icon);
        }
    }
}

// what the App, the icon and the flows ask

// Opens the window, or brings it back
pub fn show() {
    let exists = HOME.with(|cell| cell.try_borrow().map(|home| home.is_some()).unwrap_or(true));
    if !exists {
        let Some(overview) = with_app(|app| app.overview()) else { return };
        let Some(home) = Home::open(overview) else { return };
        HOME.with(|cell| {
            if let Ok(mut slot) = cell.try_borrow_mut() {
                *slot = Some(home);
            }
        });
    }
    refresh();
    with_home(|home| {
        unsafe {
            if IsIconic(home.hwnd) != 0 {
                ShowWindow(home.hwnd, SW_RESTORE);
            } else {
                ShowWindow(home.hwnd, SW_SHOW);
            }
            SetForegroundWindow(home.hwnd);
        }
        home.sync();
        home.layout();
    });
}

// the overview of the App, every second and after each change
pub fn refresh() {
    let open = HOME.with(|cell| cell.try_borrow().map(|home| home.is_some()).unwrap_or(false));
    if !open {
        return;
    }
    let Some(overview) = with_app(|app| app.overview()) else { return };
    with_home(|home| home.update(overview));
}

// at the end of the app
pub fn close() {
    let home = HOME.with(|cell| cell.try_borrow_mut().ok().and_then(|mut slot| slot.take()));
    drop(home);
}

fn hide() {
    let first = !settings::close_notice_shown();
    with_home(|home| {
        home.save_place();
        unsafe { ShowWindow(home.hwnd, SW_HIDE) };
    });
    if first {
        settings::set_close_notice_shown();
        with_app(|app| app.shell.notify(&strings::notice_still_running(), false));
    }
}

fn run(action: Action) {
    let owner = with_home_ref(|home| home.hwnd).unwrap_or(ptr::null_mut());
    match action {
        Action::More(button) => more_menu(owner, button),
        Action::Back => {
            with_home(|home| home.show_list());
        }
        Action::Add => flows::import_from_file(owner),
        Action::StartService => {
            if let Err(error) = setup::start_service() {
                message_box(owner, &error, MB_ICONERROR);
            }
            with_app(|app| app.list_soon());
        }
        Action::Open(name) => {
            with_home(|home| home.show_page(&name));
        }
        Action::Toggle(name, on) => {
            with_app(|app| if on { app.disconnect(&name) } else { app.connect(&name) });
        }
        Action::LogIn(name) => {
            with_app(|app| app.show_login(&name, None));
        }
        Action::Forget => {
            if let Some((page, username)) = with_home_ref(|home| home.saved_login()).flatten() {
                if !creds::save(&page, &username, None) {
                    log!("can't forget the password of {}", page);
                }
            }
            with_home(|home| home.reload_login());
        }
        Action::Save => save(owner),
        Action::Details(name) => {
            with_app(|app| app.show_details(&name));
        }
        Action::Remove(name) => flows::remove(owner, &name),
    }
    refresh();
}

// the username, then the name: the login doesn't depend on the name
fn save(owner: HWND) {
    let Some(changes) = with_home_ref(|home| home.changes()).flatten() else { return };
    if let Some((page, username)) = &changes.username {
        // the password saved was the one of the other username
        let saved = if username.is_empty() {
            creds::delete(page);
            true
        } else {
            creds::save(page, username, None)
        };
        if !saved {
            log!("can't save the username for {}", page);
        }
    }
    if let Some(new_name) = &changes.new_name {
        if flows::rename(owner, &changes.name, new_name) {
            with_home(|home| home.page_renamed(new_name));
        }
    }
    with_home(|home| {
        home.reload_login();
        unsafe { InvalidateRect(home.hwnd, ptr::null(), 0) };
    });
}

fn more_menu(owner: HWND, button: HWND) {
    let service_down = with_app(|app| app.service_state() == ServiceState::Unavailable).unwrap_or(false);
    let open_at_sign_in = settings::open_at_sign_in();
    let chosen = unsafe {
        let menu: HMENU = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, MENU_ADD, wide(strings::MENU_IMPORT).as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        AppendMenuW(menu, MF_STRING | if open_at_sign_in { MF_CHECKED } else { 0 }, MENU_SIGN_IN, wide(strings::MENU_OPEN_AT_SIGN_IN).as_ptr());
        let logs = CreatePopupMenu();
        AppendMenuW(logs, MF_STRING, MENU_APP_LOG, wide(strings::MENU_APP_LOG).as_ptr());
        AppendMenuW(logs, MF_STRING, MENU_SERVICE_LOG, wide(strings::MENU_SERVICE_LOG).as_ptr());
        AppendMenuW(menu, MF_POPUP, logs as usize, wide(strings::MENU_LOGS).as_ptr());
        if service_down {
            AppendMenuW(menu, MF_STRING, MENU_START_SERVICE, wide(strings::MENU_START_SERVICE).as_ptr());
        }
        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, wide(&strings::menu_version(VERSION)).as_ptr());
        AppendMenuW(menu, MF_STRING, MENU_QUIT, wide(strings::MENU_QUIT).as_ptr());
        let mut place: RECT = zeroed();
        GetWindowRect(button, &mut place);
        let chosen = TrackPopupMenuEx(menu, TPM_RETURNCMD | TPM_RIGHTALIGN | TPM_TOPALIGN, place.right, place.bottom, owner, ptr::null());
        DestroyMenu(menu);
        chosen as usize
    };
    match chosen {
        MENU_ADD => flows::import_from_file(owner),
        MENU_SIGN_IN => settings::set_open_at_sign_in(!open_at_sign_in),
        MENU_APP_LOG => {
            if let Some(path) = log::path() {
                open_in_notepad(&path);
            }
        }
        MENU_SERVICE_LOG => open_in_notepad(&crate::service::log_path()),
        MENU_START_SERVICE => run(Action::StartService),
        MENU_QUIT => flows::quit(true),
        _ => {}
    }
}

// the .conf files dropped on the window, one after the other
fn dropped(drop: HDROP) {
    let count = unsafe { DragQueryFileW(drop, u32::MAX, ptr::null_mut(), 0) };
    let mut paths = Vec::new();
    for index in 0..count {
        let length = unsafe { DragQueryFileW(drop, index, ptr::null_mut(), 0) };
        let mut buffer = vec![0u16; length as usize + 1];
        unsafe { DragQueryFileW(drop, index, buffer.as_mut_ptr(), buffer.len() as u32) };
        paths.push(crate::win::path_from_wide(&buffer));
    }
    unsafe { DragFinish(drop) };
    let owner = with_home_ref(|home| home.hwnd).unwrap_or(ptr::null_mut());
    unsafe { SetForegroundWindow(owner) };
    for path in paths {
        flows::import_path(owner, &path);
    }
    refresh();
}

// A click, Enter or Esc
fn command(wparam: WPARAM, lparam: LPARAM) {
    let control = lparam as HWND;
    let code = (wparam >> 16) as u32 & 0xffff;
    let id = low_word(wparam) as i32;
    if control.is_null() {
        // the keys of IsDialogMessage
        match id {
            IDOK => {
                let focus = unsafe { GetFocus() };
                let action = with_home_ref(|home| match home.kind_of(focus) {
                    Some(_) => home.action(focus, None),
                    None => home.page.as_ref().map(|_| Action::Save),
                })
                .flatten();
                if let Some(action) = action {
                    run(action);
                }
            }
            IDCANCEL => {
                let on_page = with_home_ref(|home| home.page.is_some()).unwrap_or(false);
                if on_page {
                    run(Action::Back);
                }
            }
            _ => {}
        }
        return;
    }
    match code {
        BN_CLICKED => {
            let click = CLICK.take().filter(|(hwnd, _)| *hwnd == control).map(|(_, point)| point);
            if let Some(action) = with_home_ref(|home| home.action(control, click)).flatten() {
                run(action);
            }
        }
        EN_CHANGE => {
            with_home(|home| {
                home.update_save();
                home.layout_panel();
            });
        }
        EN_SETFOCUS | EN_KILLFOCUS => {
            with_home_ref(|home| unsafe { InvalidateRect(home.panel, ptr::null(), 0) });
        }
        _ => {}
    }
}

// painted now, or again when the window is free
fn paint(hwnd: HWND, draw: impl FnOnce(&Home, HDC, i32, i32)) {
    let mut paint: PAINTSTRUCT = unsafe { zeroed() };
    let dc = unsafe { BeginPaint(hwnd, &mut paint) };
    let (width, height) = client_size(hwnd);
    let done = with_home_ref(|home| {
        let buffer = Buffer::new(dc, width, height);
        draw(home, buffer.dc(), width, height);
    });
    unsafe { EndPaint(hwnd, &paint) };
    if done.is_none() {
        unsafe { PostMessageW(hwnd, WM_APP_REDRAW, 0, 0) };
    }
}

fn draw_item(hwnd: HWND, lparam: LPARAM) {
    let item = unsafe { &*(lparam as *const DRAWITEMSTRUCT) };
    if with_home_ref(|home| home.draw_item(item)).is_none() {
        unsafe { PostMessageW(hwnd, WM_APP_REDRAW, item.hwndItem as usize, 0) };
    }
}

fn wheel(wparam: WPARAM) {
    let delta = ((wparam >> 16) & 0xffff) as i16 as i32;
    with_home(|home| {
        let step = home.s(SCROLL_LINE) * 2;
        home.scroll_to(home.scroll - delta * step / 120);
    });
}

unsafe extern "system" fn window_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match message {
        WM_PAINT => {
            paint(hwnd, |home, dc, width, height| home.paint_header(dc, width, height));
            return 0;
        }
        WM_ERASEBKGND => return 1,
        WM_DRAWITEM => {
            draw_item(hwnd, lparam);
            return 1;
        }
        WM_COMMAND => {
            command(wparam, lparam);
            return 0;
        }
        WM_SIZE => {
            with_home(|home| home.layout());
            return 0;
        }
        WM_GETMINMAXINFO => {
            let dpi = GetDpiForWindow(hwnd);
            let mut size = rect(0, 0, scale(MIN_WIDTH, dpi), scale(MIN_HEIGHT, dpi));
            AdjustWindowRectExForDpi(&mut size, STYLE, 0, EX_STYLE, dpi);
            let info = &mut *(lparam as *mut MINMAXINFO);
            info.ptMinTrackSize = POINT { x: size.right - size.left, y: size.bottom - size.top };
            return 0;
        }
        WM_DPICHANGED => {
            let suggested = *(lparam as *const RECT);
            with_home(|home| home.dpi_changed(low_word(wparam), &suggested));
            return 0;
        }
        WM_SETTINGCHANGE | WM_SYSCOLORCHANGE => {
            with_home(|home| home.colors_changed());
        }
        WM_DROPFILES => {
            dropped(wparam as HDROP);
            return 0;
        }
        WM_MOUSEWHEEL => {
            wheel(wparam);
            return 0;
        }
        WM_CLOSE => {
            hide();
            return 0;
        }
        WM_APP_REDRAW => {
            let target = if wparam == 0 { hwnd } else { wparam as HWND };
            InvalidateRect(target, ptr::null(), 0);
            return 0;
        }
        WM_DESTROY => remove_dialog(hwnd),
        _ => {}
    }
    DefWindowProcW(hwnd, message, wparam, lparam)
}

unsafe extern "system" fn panel_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match message {
        WM_PAINT => {
            paint(hwnd, |home, dc, width, height| home.paint_panel(dc, width, height));
            return 0;
        }
        WM_ERASEBKGND => return 1,
        WM_DRAWITEM => {
            draw_item(hwnd, lparam);
            return 1;
        }
        WM_COMMAND => {
            command(wparam, lparam);
            return 0;
        }
        // the text fields, on the white of their card, or greyed when they can't change
        WM_CTLCOLOREDIT | WM_CTLCOLORSTATIC => {
            let dc = wparam as HDC;
            let colors = with_home_ref(|home| {
                let locked = message == WM_CTLCOLORSTATIC;
                let (text, back, brush) = if locked {
                    (home.palette.muted, home.palette.background, home.background_brush)
                } else {
                    (home.palette.text, home.palette.surface, home.surface_brush)
                };
                (text, back, brush)
            });
            if let Some((text, back, brush)) = colors {
                SetTextColor(dc, text);
                SetBkColor(dc, back);
                return brush as LRESULT;
            }
        }
        WM_VSCROLL => {
            with_home(|home| home.on_scroll(low_word(wparam) as i32));
            return 0;
        }
        WM_MOUSEWHEEL => {
            wheel(wparam);
            return 0;
        }
        WM_APP_HOVER => {
            with_home_ref(|home| home.hovered(wparam as HWND));
            return 0;
        }
        WM_APP_REVEAL => {
            with_home(|home| home.reveal(wparam as HWND));
            return 0;
        }
        WM_APP_REDRAW => {
            let target = if wparam == 0 { hwnd } else { wparam as HWND };
            InvalidateRect(target, ptr::null(), 0);
            return 0;
        }
        _ => {}
    }
    DefWindowProcW(hwnd, message, wparam, lparam)
}

// The buttons: the hand over them, where the mouse is, where the click was, into view with the focus
unsafe extern "system" fn button_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM, _id: usize, _data: usize) -> LRESULT {
    match message {
        WM_MOUSEMOVE => {
            let (hot, _) = HOT.get();
            HOT.set((hwnd, point_of(lparam)));
            if hot != hwnd {
                let mut track = TRACKMOUSEEVENT { cbSize: size_of::<TRACKMOUSEEVENT>() as u32, dwFlags: TME_LEAVE, hwndTrack: hwnd, dwHoverTime: 0 };
                TrackMouseEvent(&mut track);
                InvalidateRect(hwnd, ptr::null(), 0);
                if !hot.is_null() {
                    InvalidateRect(hot, ptr::null(), 0);
                }
            }
            PostMessageW(GetParent(hwnd), WM_APP_HOVER, hwnd as usize, 0);
        }
        WM_MOUSELEAVE => {
            if HOT.get().0 == hwnd {
                HOT.set((ptr::null_mut(), POINT { x: 0, y: 0 }));
            }
            HOT_PART.set((ptr::null_mut(), Part::Nothing));
            InvalidateRect(hwnd, ptr::null(), 0);
        }
        WM_LBUTTONUP => CLICK.set(Some((hwnd, point_of(lparam)))),
        WM_KEYDOWN => CLICK.set(None),
        WM_SETCURSOR => {
            SetCursor(LoadCursorW(ptr::null_mut(), IDC_HAND));
            return 1;
        }
        WM_SETFOCUS => {
            PostMessageW(GetParent(hwnd), WM_APP_REVEAL, hwnd as usize, 0);
        }
        WM_NCDESTROY => {
            RemoveWindowSubclass(hwnd, Some(button_proc), 1);
            if HOT.get().0 == hwnd {
                HOT.set((ptr::null_mut(), POINT { x: 0, y: 0 }));
            }
        }
        _ => {}
    }
    DefSubclassProc(hwnd, message, wparam, lparam)
}
