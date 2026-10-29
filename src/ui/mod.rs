// The app next to the clock and its main window, with plain Win32 windows: the state lives in one App (client/) on the thread of the
// windows, reached through with_app(). The modal steps (menus, message boxes, file dialogs, UAC) run outside of
// it, in flows.rs, so that the messages they pump find the App free.

pub mod connect;
pub mod details;
pub mod flows;
pub mod home;
pub mod theme;
pub mod tray;

use std::cell::RefCell;
use std::mem::{size_of, zeroed};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{HINSTANCE, HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontIndirectW, DeleteObject, DrawTextW, GetDC, GetTextMetricsW, ReleaseDC, SelectObject, DT_CALCRECT,
    DT_NOPREFIX, DT_SINGLELINE, DT_WORDBREAK, FW_SEMIBOLD, HFONT, TEXTMETRICW,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::SystemParametersInfoForDpi;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DispatchMessageW, GetAncestor, GetMessageW, GetWindowTextLengthW, GetWindowTextW, IsDialogMessageW,
    MessageBoxW, MoveWindow, SendMessageW, SetWindowTextW, TranslateMessage, GA_ROOT, HMENU, MESSAGEBOX_RESULT,
    MESSAGEBOX_STYLE, MSG, NONCLIENTMETRICSW, SPI_GETNONCLIENTMETRICS, SW_SHOWNORMAL, WM_APP, WM_SETFONT, WS_CHILD,
    WS_VISIBLE,
};

use crate::names::PRODUCT;
use crate::win::{wide, wide_path};

pub const WM_APP_EVENT: u32 = WM_APP + 1;
pub const WM_APP_TRAY: u32 = WM_APP + 2;
pub const WM_APP_SHOW: u32 = WM_APP + 3;
pub const WM_APP_QUIT: u32 = WM_APP + 4;
pub const WM_APP_IMPORT: u32 = WM_APP + 5;
// the main window, out of the App
pub const WM_APP_HOME: u32 = WM_APP + 6;
// the tests open the details of a tunnel by its place in the list: a menu can't be driven from outside
#[cfg(feature = "testing")]
pub const WM_APP_TEST_DETAILS: u32 = WM_APP + 100;

pub use crate::client::Startup;

pub fn instance() -> HINSTANCE {
    unsafe { GetModuleHandleW(ptr::null()) }
}

pub fn scale(value: i32, dpi: u32) -> i32 {
    (value * dpi as i32 + 48) / 96
}

// The fonts of the dialogs of Windows, at the scale of a display
pub struct Fonts {
    pub normal: HFONT,
    pub heading: HFONT,
    pub large: HFONT,
}

impl Fonts {
    pub fn new(dpi: u32) -> Fonts {
        let mut metrics: NONCLIENTMETRICSW = unsafe { zeroed() };
        metrics.cbSize = size_of::<NONCLIENTMETRICSW>() as u32;
        unsafe {
            SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, metrics.cbSize, &mut metrics as *mut _ as *mut _, 0, dpi)
        };
        let base = metrics.lfMessageFont;
        let mut heading = base;
        heading.lfHeight = base.lfHeight * 3 / 2;
        heading.lfWeight = FW_SEMIBOLD as i32;
        let mut large = base;
        large.lfHeight = base.lfHeight * 13 / 10;
        unsafe {
            Fonts {
                normal: CreateFontIndirectW(&base),
                heading: CreateFontIndirectW(&heading),
                large: CreateFontIndirectW(&large),
            }
        }
    }
}

impl Drop for Fonts {
    fn drop(&mut self) {
        unsafe {
            DeleteObject(self.normal as _);
            DeleteObject(self.heading as _);
            DeleteObject(self.large as _);
        }
    }
}

// A control of a window, at its place once the window makes its layout
pub fn child(parent: HWND, class: &str, text: &str, style: u32, ex_style: u32, id: i32) -> HWND {
    unsafe {
        CreateWindowExW(
            ex_style,
            wide(class).as_ptr(),
            wide(text).as_ptr(),
            WS_CHILD | WS_VISIBLE | style,
            0,
            0,
            10,
            10,
            parent,
            id as usize as HMENU,
            instance(),
            ptr::null(),
        )
    }
}

pub fn place(window: HWND, x: i32, y: i32, width: i32, height: i32) {
    unsafe { MoveWindow(window, x, y, width, height, 1) };
}

pub fn set_font(window: HWND, font: HFONT) {
    unsafe { SendMessageW(window, WM_SETFONT, font as usize, 1) };
}

pub fn set_text(window: HWND, text: &str) {
    unsafe { SetWindowTextW(window, wide(text).as_ptr()) };
}

pub fn get_text(window: HWND) -> String {
    let length = unsafe { GetWindowTextLengthW(window) };
    if length <= 0 {
        return String::new();
    }
    let mut buffer = vec![0u16; length as usize + 1];
    let copied = unsafe { GetWindowTextW(window, buffer.as_mut_ptr(), buffer.len() as i32) };
    String::from_utf16_lossy(&buffer[..copied.max(0) as usize])
}

// The size of a text in a font: on one line, or wrapped at the width
pub fn measure(window: HWND, font: HFONT, text: &str, width: Option<i32>) -> (i32, i32) {
    let text: Vec<u16> = if text.is_empty() { "X".encode_utf16().collect() } else { text.encode_utf16().collect() };
    let mut rect = RECT { left: 0, top: 0, right: width.unwrap_or(10_000), bottom: 0 };
    let format = DT_CALCRECT | DT_NOPREFIX | if width.is_some() { DT_WORDBREAK } else { DT_SINGLELINE };
    unsafe {
        let dc = GetDC(window);
        let previous = SelectObject(dc, font as _);
        DrawTextW(dc, text.as_ptr(), text.len() as i32, &mut rect, format);
        SelectObject(dc, previous);
        ReleaseDC(window, dc);
    }
    (rect.right - rect.left, rect.bottom - rect.top)
}

pub fn line_height(window: HWND, font: HFONT) -> i32 {
    let mut metrics: TEXTMETRICW = unsafe { zeroed() };
    unsafe {
        let dc = GetDC(window);
        let previous = SelectObject(dc, font as _);
        GetTextMetricsW(dc, &mut metrics);
        SelectObject(dc, previous);
        ReleaseDC(window, dc);
    }
    metrics.tmHeight
}

pub fn message_box(owner: HWND, text: &str, style: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    unsafe { MessageBoxW(owner, wide(text).as_ptr(), wide(PRODUCT).as_ptr(), style) }
}

pub fn open_in_notepad(path: &Path) {
    let arguments = format!("\"{}\"", path.display());
    unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            wide("open").as_ptr(),
            wide("notepad.exe").as_ptr(),
            wide(&arguments).as_ptr(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    let _ = wide_path(path);
}

thread_local! {
    // the windows where Tab, Enter and Esc work as in a dialog
    static DIALOGS: RefCell<Vec<HWND>> = const { RefCell::new(Vec::new()) };
}

pub fn add_dialog(window: HWND) {
    DIALOGS.with(|dialogs| dialogs.borrow_mut().push(window));
}

pub fn remove_dialog(window: HWND) {
    DIALOGS.with(|dialogs| dialogs.borrow_mut().retain(|&item| item != window));
}

fn is_dialog(window: HWND) -> bool {
    DIALOGS.with(|dialogs| dialogs.borrow().contains(&window))
}

pub fn message_loop() {
    let mut message: MSG = unsafe { zeroed() };
    while unsafe { GetMessageW(&mut message, ptr::null_mut(), 0, 0) } > 0 {
        let root = unsafe { GetAncestor(message.hwnd, GA_ROOT) };
        if !root.is_null() && is_dialog(root) && unsafe { IsDialogMessageW(root, &message) } != 0 {
            continue;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

pub fn run(startup: Startup) -> i32 {
    tray::run(startup)
}
