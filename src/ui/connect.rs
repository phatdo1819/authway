// The window that connects a VPN whose server requires a login: username, password and the code of the
// authenticator app. It opens as the tunnel comes up, so the user types while it connects.

use std::mem::{replace, size_of, zeroed};
use std::ptr;
use std::sync::Once;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, GetSysColor, GetSysColorBrush, MonitorFromPoint, RedrawWindow, SetBkColor, SetTextColor,
    COLOR_WINDOW, COLOR_WINDOWTEXT, HDC, MONITORINFO, MONITOR_DEFAULTTONEAREST, RDW_ALLCHILDREN, RDW_ERASE, RDW_FRAME,
    RDW_INVALIDATE,
};
use windows_sys::Win32::System::SystemServices::SS_NOPREFIX;
use windows_sys::Win32::UI::Controls::{BST_CHECKED, BST_UNCHECKED, EM_SETCUEBANNER, EM_SETLIMITTEXT, EM_SETSEL};
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetCursorPos, GetDlgCtrlID, GetWindowRect, IsIconic, LoadImageW,
    RegisterClassExW, SendMessageW, SetForegroundWindow, SetWindowPos, ShowWindow, BM_GETCHECK, BM_SETCHECK,
    BN_CLICKED, BS_AUTOCHECKBOX, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, DC_HASDEFID, DM_GETDEFID,
    EN_CHANGE, ES_AUTOHSCROLL, ES_NUMBER, ES_PASSWORD, HWND_NOTOPMOST, HWND_TOPMOST, IDCANCEL, IDOK, IMAGE_ICON,
    LR_DEFAULTCOLOR, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SW_HIDE, SW_RESTORE, SW_SHOW, WM_CLOSE,
    WM_COMMAND, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED, WNDCLASSEXW, WS_CAPTION, WS_CLIPCHILDREN,
    WS_EX_APPWINDOW, WS_EX_CLIENTEDGE, WS_EX_CONTROLPARENT, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP,
};

use super::tray::with_app;
use super::{
    add_dialog, child, get_text, instance, line_height, measure, place_all, remove_dialog, scale, set_font, set_text,
    Fonts,
};
use crate::client::{LoginValues, LoginView, OTP_LENGTH};
use crate::creds::SavedLogin;
use crate::log;
use crate::names::PRODUCT;
use crate::strings;
use crate::win::wide;

const CLASS: &str = "AuthwayConnect";
// it never paints over its fields, which move when the texts above them change
const STYLE: u32 = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
const EX_STYLE: u32 = WS_EX_APPWINDOW | WS_EX_CONTROLPARENT;

const ID_HEADING: i32 = 100;
const ID_HINT: i32 = 101;
const ID_NOTICE: i32 = 102;
const ID_USERNAME: i32 = 104;
const ID_PASSWORD: i32 = 106;
const ID_REMEMBER: i32 = 107;
const ID_CODE: i32 = 109;
const ID_ERROR: i32 = 110;

// COLORREF is 0x00bbggrr
const ERROR_COLOR: u32 = 0x001c_1cb9;
const NOTICE_COLOR: u32 = 0x0012_349a;

pub struct ConnectWindow {
    pub hwnd: HWND,
    pub tunnel: String,
    pub busy: bool,
    dpi: u32,
    fonts: Fonts,
    heading: HWND,
    hint: HWND,
    notice: HWND,
    username_label: HWND,
    username: HWND,
    password_label: HWND,
    password: HWND,
    remember: HWND,
    code_label: HWND,
    code: HWND,
    error: HWND,
    ok: HWND,
    cancel: HWND,
    otp_required: bool,
    can_remember: bool,
    has_notice: bool,
    has_error: bool,
}

fn register_class() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| unsafe {
        let class = wide(CLASS);
        let mut info: WNDCLASSEXW = zeroed();
        info.cbSize = size_of::<WNDCLASSEXW>() as u32;
        info.lpfnWndProc = Some(window_proc);
        info.hInstance = instance();
        info.hIcon = LoadImageW(instance(), 1 as _, IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR) as _;
        info.hIconSm = LoadImageW(instance(), 1 as _, IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR) as _;
        info.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
        info.lpszClassName = class.as_ptr();
        if RegisterClassExW(&info) == 0 {
            log!("can't register the window: {}", crate::win::last_error_message());
        }
    });
}

fn show(window: HWND, visible: bool) {
    unsafe { ShowWindow(window, if visible { SW_SHOW } else { SW_HIDE }) };
}

impl ConnectWindow {
    pub fn open(
        tunnel: &str,
        heading: &str,
        hint: &str,
        saved: &SavedLogin,
        can_remember: bool,
        otp_required: bool,
        notice: Option<&str>,
    ) -> Option<ConnectWindow> {
        register_class();
        // on the display with the mouse
        let mut cursor = POINT { x: 0, y: 0 };
        let mut monitor: MONITORINFO = unsafe { zeroed() };
        monitor.cbSize = size_of::<MONITORINFO>() as u32;
        unsafe {
            GetCursorPos(&mut cursor);
            GetMonitorInfoW(MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST), &mut monitor);
        }
        let work = monitor.rcWork;
        let hwnd = unsafe {
            CreateWindowExW(
                EX_STYLE,
                wide(CLASS).as_ptr(),
                wide(PRODUCT).as_ptr(),
                STYLE,
                work.left + 100,
                work.top + 100,
                200,
                200,
                ptr::null_mut(),
                ptr::null_mut(),
                instance(),
                ptr::null(),
            )
        };
        if hwnd.is_null() {
            log!("can't open the window: {}", crate::win::last_error_message());
            return None;
        }
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        let fonts = Fonts::new(dpi);
        let label = SS_NOPREFIX;
        let edit = WS_TABSTOP | ES_AUTOHSCROLL as u32;
        let mut window = ConnectWindow {
            hwnd,
            tunnel: tunnel.to_string(),
            busy: false,
            dpi,
            heading: child(hwnd, "STATIC", heading, label, 0, ID_HEADING),
            hint: child(hwnd, "STATIC", hint, label, 0, ID_HINT),
            notice: child(hwnd, "STATIC", "", label, 0, ID_NOTICE),
            username_label: child(hwnd, "STATIC", strings::LOGIN_USERNAME, label, 0, 0),
            username: child(hwnd, "EDIT", &saved.username, edit, WS_EX_CLIENTEDGE, ID_USERNAME),
            password_label: child(hwnd, "STATIC", strings::LOGIN_PASSWORD, label, 0, 0),
            password: child(hwnd, "EDIT", "", edit | ES_PASSWORD as u32, WS_EX_CLIENTEDGE, ID_PASSWORD),
            remember: child(hwnd, "BUTTON", strings::LOGIN_REMEMBER, WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, ID_REMEMBER),
            code_label: child(hwnd, "STATIC", strings::LOGIN_OTP, label, 0, 0),
            code: child(hwnd, "EDIT", "", edit | ES_NUMBER as u32, WS_EX_CLIENTEDGE, ID_CODE),
            error: child(hwnd, "STATIC", "", label, 0, ID_ERROR),
            ok: child(hwnd, "BUTTON", strings::LOGIN_CONNECT, WS_TABSTOP | BS_DEFPUSHBUTTON as u32, 0, IDOK),
            cancel: child(hwnd, "BUTTON", strings::CANCEL, WS_TABSTOP | BS_PUSHBUTTON as u32, 0, IDCANCEL),
            fonts,
            otp_required,
            can_remember,
            has_notice: false,
            has_error: false,
        };
        window.apply_fonts();
        unsafe {
            // a pasted code can have spaces, which go away
            SendMessageW(window.code, EM_SETLIMITTEXT, 16, 0);
            SendMessageW(window.code, EM_SETCUEBANNER, 0, wide(strings::LOGIN_OTP_CUE).as_ptr() as LPARAM);
        }
        if can_remember {
            if let Some(password) = &saved.password {
                set_text(window.password, password);
            }
        }
        // checked the first time, then as the user left it
        let checked = can_remember && (saved.password.is_some() || saved.username.is_empty());
        unsafe { SendMessageW(window.remember, BM_SETCHECK, if checked { BST_CHECKED } else { BST_UNCHECKED } as usize, 0) };
        show(window.remember, can_remember);
        window.set_notice(notice);
        window.layout();
        // in the middle of the display, above the other windows the first time
        let mut rect: RECT = unsafe { zeroed() };
        unsafe { GetWindowRect(hwnd, &mut rect) };
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        let x = work.left + (work.right - work.left - width) / 2;
        let y = work.top + (work.bottom - work.top - height) / 2;
        unsafe {
            SetWindowPos(hwnd, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE);
            ShowWindow(hwnd, SW_SHOW);
            SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE);
            SetForegroundWindow(hwnd);
        }
        add_dialog(hwnd);
        window.focus_first_empty();
        Some(window)
    }

    fn apply_fonts(&self) {
        for control in [
            self.hint,
            self.notice,
            self.username_label,
            self.username,
            self.password_label,
            self.password,
            self.remember,
            self.code_label,
            self.error,
            self.ok,
            self.cancel,
        ] {
            set_font(control, self.fonts.normal);
        }
        set_font(self.heading, self.fonts.heading);
        set_font(self.code, self.fonts.large);
    }

    // The sizes follow the font, which follows the scale of the display. The fields move all at once, then the window
    // paints again with them: the heading, the hint, the notice and the error change their places
    fn layout(&self) {
        let hwnd = self.hwnd;
        let mut places = Vec::new();
        let mut place = |window: HWND, x: i32, y: i32, width: i32, height: i32| places.push((window, x, y, width, height));
        let s = |value: i32| scale(value, self.dpi);
        let normal = self.fonts.normal;
        let margin = s(22);
        let width = s(360);
        let gap = s(10);
        let line = line_height(hwnd, normal);
        let edit_height = line + s(10);
        let label_width = [strings::LOGIN_USERNAME, strings::LOGIN_PASSWORD, strings::LOGIN_OTP]
            .iter()
            .map(|text| measure(hwnd, normal, text, None).0)
            .max()
            .unwrap_or(0);
        let field_x = margin + label_width + s(14);
        let field_width = margin + width - field_x;
        let mut y = margin;

        let (_, height) = measure(hwnd, self.fonts.heading, &get_text(self.heading), Some(width));
        place(self.heading, margin, y, width, height);
        y += height + s(6);
        let (_, height) = measure(hwnd, normal, &get_text(self.hint), Some(width));
        place(self.hint, margin, y, width, height);
        y += height + s(14);
        show(self.notice, self.has_notice);
        if self.has_notice {
            let (_, height) = measure(hwnd, normal, &get_text(self.notice), Some(width));
            place(self.notice, margin, y, width, height);
            y += height + s(12);
        }
        for (label, field) in [(self.username_label, self.username), (self.password_label, self.password)] {
            place(label, margin, y + (edit_height - line) / 2, label_width, line);
            place(field, field_x, y, field_width, edit_height);
            y += edit_height + gap;
        }
        if self.can_remember {
            let height = line + s(6);
            place(self.remember, field_x, y - s(4), field_width, height);
            y += height + gap - s(4);
        }
        show(self.code_label, self.otp_required);
        show(self.code, self.otp_required);
        if self.otp_required {
            let code_height = line_height(hwnd, self.fonts.large) + s(10);
            place(self.code_label, margin, y + (code_height - line) / 2, label_width, line);
            place(self.code, field_x, y, s(120), code_height);
            y += code_height + gap;
        }
        show(self.error, self.has_error);
        if self.has_error {
            let (_, height) = measure(hwnd, normal, &get_text(self.error), Some(width));
            place(self.error, margin, y + s(2), width, height);
            y += height + gap + s(2);
        }
        y += s(8);
        let button_height = edit_height + s(4);
        let button_width = [strings::LOGIN_CONNECT, strings::LOGIN_BUSY, strings::CANCEL]
            .iter()
            .map(|text| measure(hwnd, normal, text, None).0 + s(32))
            .max()
            .unwrap_or(0)
            .max(s(96));
        let cancel_x = margin + width - button_width;
        place(self.cancel, cancel_x, y, button_width, button_height);
        place(self.ok, cancel_x - s(8) - button_width, y, button_width, button_height);
        y += button_height + margin;
        place_all(&places);

        let mut rect = RECT { left: 0, top: 0, right: margin * 2 + width, bottom: y };
        unsafe {
            AdjustWindowRectExForDpi(&mut rect, STYLE, 0, EX_STYLE, self.dpi);
            SetWindowPos(
                hwnd,
                ptr::null_mut(),
                0,
                0,
                rect.right - rect.left,
                rect.bottom - rect.top,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
            RedrawWindow(hwnd, ptr::null(), ptr::null_mut(), RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
        }
    }

    pub fn dpi_changed(&mut self, dpi: u32, suggested: &RECT) {
        self.dpi = dpi;
        let previous = replace(&mut self.fonts, Fonts::new(dpi));
        self.apply_fonts();
        drop(previous);
        unsafe {
            SetWindowPos(self.hwnd, ptr::null_mut(), suggested.left, suggested.top, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE)
        };
        self.layout();
    }

    pub fn set_heading(&mut self, text: &str) {
        if get_text(self.heading) != text {
            set_text(self.heading, text);
            self.layout();
        }
    }

    pub fn set_hint(&mut self, text: &str) {
        if get_text(self.hint) != text {
            set_text(self.hint, text);
            self.layout();
        }
    }

    pub fn set_notice(&mut self, text: Option<&str>) {
        let text = text.unwrap_or("");
        self.has_notice = !text.is_empty();
        set_text(self.notice, text);
        self.layout();
    }

    pub fn set_error(&mut self, text: Option<&str>) {
        let text = text.unwrap_or("");
        if self.has_error != text.is_empty() && get_text(self.error) == text {
            return;
        }
        self.has_error = !text.is_empty();
        set_text(self.error, text);
        self.layout();
    }

    pub fn otp_required(&self) -> bool {
        self.otp_required
    }

    pub fn set_otp_required(&mut self, required: bool) {
        if self.otp_required != required {
            self.otp_required = required;
            self.layout();
        }
    }

    pub fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
        for control in [self.username, self.password, self.remember, self.code, self.ok] {
            unsafe { EnableWindow(control, (!busy) as i32) };
        }
        set_text(self.ok, if busy { strings::LOGIN_BUSY } else { strings::LOGIN_CONNECT });
        if !busy {
            self.focus_first_empty();
        }
    }

    pub fn values(&self) -> LoginValues {
        let checked = unsafe { SendMessageW(self.remember, BM_GETCHECK, 0, 0) } as u32 == BST_CHECKED;
        LoginValues {
            username: get_text(self.username).trim().to_string(),
            password: get_text(self.password),
            code: get_text(self.code),
            remember: self.can_remember && checked,
        }
    }

    fn focus(&self, control: HWND) {
        unsafe {
            SetFocus(control);
            SendMessageW(control, EM_SETSEL, 0, -1isize as LPARAM);
        }
    }

    pub fn focus_first_empty(&self) {
        let values = self.values();
        if values.username.is_empty() {
            self.focus(self.username);
        } else if values.password.is_empty() {
            self.focus(self.password);
        } else if self.otp_required {
            self.focus(self.code);
        } else {
            unsafe { SetFocus(self.ok) };
        }
    }

    // after a refused login: a code is good once
    pub fn clear_code(&self) {
        set_text(self.code, "");
        if self.otp_required {
            self.focus(self.code);
        } else {
            self.focus(self.password);
        }
    }

    // Only the digits of a pasted code stay; true when the sixth one makes the login complete
    pub fn code_changed(&self) -> bool {
        let text = get_text(self.code);
        let digits: String = text.chars().filter(char::is_ascii_digit).take(OTP_LENGTH).collect();
        if digits != text {
            set_text(self.code, &digits);
            unsafe { SendMessageW(self.code, EM_SETSEL, digits.len(), digits.len() as LPARAM) };
        }
        let values = self.values();
        !self.busy && digits.len() == OTP_LENGTH && !values.username.is_empty() && !values.password.is_empty()
    }

    pub fn activate(&self) {
        unsafe {
            if IsIconic(self.hwnd) != 0 {
                ShowWindow(self.hwnd, SW_RESTORE);
            }
            SetForegroundWindow(self.hwnd);
        }
    }
}

impl LoginView for ConnectWindow {
    fn set_heading(&mut self, text: &str) {
        ConnectWindow::set_heading(self, text);
    }

    fn set_hint(&mut self, text: &str) {
        ConnectWindow::set_hint(self, text);
    }

    fn set_notice(&mut self, text: Option<&str>) {
        ConnectWindow::set_notice(self, text);
    }

    fn set_error(&mut self, text: Option<&str>) {
        ConnectWindow::set_error(self, text);
    }

    fn set_otp_required(&mut self, required: bool) {
        ConnectWindow::set_otp_required(self, required);
    }

    fn set_busy(&mut self, busy: bool) {
        ConnectWindow::set_busy(self, busy);
    }

    fn values(&self) -> LoginValues {
        ConnectWindow::values(self)
    }

    fn clear_code(&self) {
        ConnectWindow::clear_code(self);
    }

    fn code_changed(&self) -> bool {
        ConnectWindow::code_changed(self)
    }

    fn activate(&self) {
        ConnectWindow::activate(self);
    }

    fn id(&self) -> usize {
        self.hwnd as usize
    }
}

impl Drop for ConnectWindow {
    fn drop(&mut self) {
        unsafe { DestroyWindow(self.hwnd) };
    }
}

fn low_word(value: usize) -> u32 {
    (value & 0xffff) as u32
}

unsafe extern "system" fn window_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match message {
        // without the App: it comes also while the App changes the texts
        WM_CTLCOLORSTATIC => {
            let dc = wparam as HDC;
            let color = match GetDlgCtrlID(lparam as HWND) {
                ID_ERROR => ERROR_COLOR,
                ID_NOTICE => NOTICE_COLOR,
                _ => GetSysColor(COLOR_WINDOWTEXT),
            };
            SetTextColor(dc, color);
            SetBkColor(dc, GetSysColor(COLOR_WINDOW));
            return GetSysColorBrush(COLOR_WINDOW) as LRESULT;
        }
        DM_GETDEFID => return ((DC_HASDEFID << 16) | IDOK as u32) as LRESULT,
        WM_COMMAND => {
            let id = low_word(wparam) as i32;
            let code = (wparam >> 16) as u32 & 0xffff;
            match id {
                IDOK if code == BN_CLICKED => {
                    with_app(|app| app.submit(hwnd as usize));
                }
                IDCANCEL => {
                    with_app(|app| app.cancel(hwnd as usize));
                }
                ID_CODE if code == EN_CHANGE => {
                    with_app(|app| app.code_changed(hwnd as usize));
                }
                _ => {}
            }
            return 0;
        }
        WM_CLOSE => {
            with_app(|app| app.cancel(hwnd as usize));
            return 0;
        }
        WM_DPICHANGED => {
            let suggested = *(lparam as *const RECT);
            with_app(|app| app.login_of(hwnd as usize).map(|window| window.dpi_changed(low_word(wparam), &suggested)));
            return 0;
        }
        WM_DESTROY => remove_dialog(hwnd),
        _ => {}
    }
    DefWindowProcW(hwnd, message, wparam, lparam)
}
