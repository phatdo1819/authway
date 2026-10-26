// The window of the details of a VPN, as the details of a network connection in Windows: its state, its routes
// (all the traffic, or only some networks), its configuration without the keys that are secret, and its login.
// It follows the tunnel every second; Ctrl+C copies the rows selected, "Copy all" all of them.

use std::mem::{replace, size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr};
use std::ptr;
use std::sync::Once;

use windows_sys::Win32::Foundation::{GlobalFree, HANDLE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, GetSysColor, GetSysColorBrush, InvalidateRect, MonitorFromPoint, SetBkColor, SetTextColor,
    COLOR_WINDOW, COLOR_WINDOWTEXT, HDC, MONITORINFO, MONITOR_DEFAULTTONEAREST,
};
use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::System::SystemServices::SS_NOPREFIX;
use windows_sys::Win32::UI::Controls::{
    SetWindowTheme, LVCF_WIDTH, LVCOLUMNW, LVGF_GROUPID, LVGF_HEADER, LVGROUP, LVIF_GROUPID, LVIF_TEXT, LVIS_SELECTED,
    LVITEMW, LVM_DELETEALLITEMS, LVM_ENABLEGROUPVIEW, LVM_GETNEXTITEM, LVM_INSERTCOLUMNW, LVM_INSERTGROUP,
    LVM_INSERTITEMW, LVM_REMOVEALLGROUPS, LVM_SETCOLUMNWIDTH, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMSTATE,
    LVM_SETITEMTEXTW, LVNI_SELECTED, LVN_KEYDOWN, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_EX_LABELTIP,
    LVS_NOCOLUMNHEADER, LVS_REPORT, LVS_SHOWSELALWAYS, NMHDR, NMLVKEYDOWN,
};
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, SetFocus, VK_CONTROL};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetClientRect, GetCursorPos, IsIconic, LoadImageW, RegisterClassExW,
    SendMessageW, SetForegroundWindow, SetWindowPos, ShowWindow, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, DC_HASDEFID,
    DM_GETDEFID, IDCANCEL, IMAGE_ICON, LR_DEFAULTCOLOR, MINMAXINFO, SWP_NOACTIVATE, SWP_NOZORDER, SW_RESTORE,
    SW_SHOW, WM_CLOSE, WM_COMMAND, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED, WM_GETMINMAXINFO, WM_NOTIFY,
    WM_SETREDRAW, WM_SIZE, WNDCLASSEXW, WS_EX_APPWINDOW, WS_EX_CONTROLPARENT, WS_OVERLAPPEDWINDOW, WS_TABSTOP,
};

use super::tray::{with_app, Session, Tunnel};
use super::{add_dialog, child, get_text, instance, line_height, measure, place, remove_dialog, scale, set_font, time, Fonts};
use crate::conf::IpNet;
use crate::log;
use crate::strings;
use crate::win::{unix_now, wide};

const CLASS: &str = "AuthwayDetails";
const STYLE: u32 = WS_OVERLAPPEDWINDOW;
const EX_STYLE: u32 = WS_EX_APPWINDOW | WS_EX_CONTROLPARENT;
const ID_HEADING: i32 = 100;
const ID_LIST: i32 = 101;
const ID_COPY: i32 = 102;
const CF_UNICODETEXT: u32 = 13;

// the groups of rows; one more per server after the first
const GROUP_CONNECTION: i32 = 1;
const GROUP_ROUTING: i32 = 2;
const GROUP_COMPUTER: i32 = 3;
const GROUP_LOGIN: i32 = 4;
const GROUP_SERVER: i32 = 10;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Group {
    pub id: i32,
    pub header: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Row {
    pub group: i32,
    pub label: String,
    pub value: String,
}

// What the window shows, in its order
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Details {
    pub groups: Vec<Group>,
    pub rows: Vec<Row>,
}

impl Details {
    fn group(&mut self, id: i32, header: impl Into<String>) {
        self.groups.push(Group { id, header: header.into() });
    }

    // in the last group
    fn row(&mut self, label: impl Into<String>, value: impl Into<String>) {
        let group = self.groups.last().map_or(0, |group| group.id);
        self.rows.push(Row { group, label: label.into(), value: value.into() });
    }

    pub fn text(&self, title: &str) -> String {
        let mut text = format!("{}\r\n", title);
        for group in &self.groups {
            text += &format!("\r\n{}\r\n", group.header);
            for row in self.rows.iter().filter(|row| row.group == group.id) {
                text += &format!("  {}: {}\r\n", row.label, row.value);
            }
        }
        text
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Routing {
    // no AllowedIPs
    None,
    // all the addresses, IPv4 and IPv6
    Full,
    // all the IPv4 addresses; some IPv6 networks too, or none
    FullIpv4 { ipv6: bool },
    FullIpv6 { ipv4: bool },
    // only some networks
    Split,
}

// Whether the networks hold all the addresses of IPv4 or IPv6: 0.0.0.0/0, or 0.0.0.0/1 with 128.0.0.0/1 as
// wg-quick writes it. Two networks are one inside the other or apart, so the ones in no other add up.
fn covers_all(nets: &[IpNet], ipv6: bool) -> bool {
    let nets: Vec<&IpNet> = nets.iter().filter(|net| net.addr.is_ipv6() == ipv6).collect();
    let bits = if ipv6 { 128 } else { 32 };
    let mut total: u128 = 0;
    for (index, net) in nets.iter().enumerate() {
        let inside = nets.iter().enumerate().any(|(other_index, other)| {
            other_index != index
                && other.contains(net.addr)
                && (other.prefix < net.prefix || (other.prefix == net.prefix && other_index < index))
        });
        if inside {
            continue;
        }
        if net.prefix == 0 {
            return true;
        }
        // 2^128 doesn't fit: going over means all of IPv6
        match total.checked_add(1u128 << (bits - u32::from(net.prefix))) {
            Some(sum) => total = sum,
            None => return true,
        }
    }
    !ipv6 && total >= 1u128 << 32
}

pub fn routing(nets: &[IpNet]) -> Routing {
    let has = |ipv6: bool| nets.iter().any(|net| net.addr.is_ipv6() == ipv6);
    match (covers_all(nets, false), covers_all(nets, true)) {
        (true, true) => Routing::Full,
        (true, false) => Routing::FullIpv4 { ipv6: has(true) },
        (false, true) => Routing::FullIpv6 { ipv4: has(false) },
        _ if nets.is_empty() => Routing::None,
        _ => Routing::Split,
    }
}

fn routing_text(routing: Routing) -> String {
    match routing {
        Routing::None => strings::ROUTING_NONE.to_string(),
        Routing::Full => strings::ROUTING_FULL.to_string(),
        Routing::FullIpv4 { ipv6 } => strings::routing_full_one("IPv4", "IPv6", ipv6),
        Routing::FullIpv6 { ipv4 } => strings::routing_full_one("IPv6", "IPv4", ipv4),
        Routing::Split => strings::ROUTING_SPLIT.to_string(),
    }
}

fn route_text(net: &IpNet) -> String {
    match net.addr {
        _ if net.prefix == 0 => strings::value_default_route(net.addr.is_ipv6()),
        IpAddr::V4(_) if net.prefix == 32 => strings::VALUE_ONE_ADDRESS.to_string(),
        IpAddr::V6(_) if net.prefix == 128 => strings::VALUE_ONE_ADDRESS.to_string(),
        IpAddr::V4(_) => strings::value_mask(&Ipv4Addr::from(u32::MAX << (32 - u32::from(net.prefix))).to_string()),
        IpAddr::V6(_) => strings::VALUE_IPV6_NETWORK.to_string(),
    }
}

// "vpn.example.com:51820" or "[2001:db8::1]:51820": the host and the port
fn split_endpoint(endpoint: &str) -> (String, String) {
    match endpoint.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {
            (host.trim_start_matches('[').trim_end_matches(']').to_string(), port.to_string())
        }
        _ => (endpoint.to_string(), String::new()),
    }
}

fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn list_or(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        empty.to_string()
    } else {
        items.join(", ")
    }
}

fn handshake_text(handshake: u64) -> String {
    if handshake == 0 {
        strings::VALUE_NOT_YET.to_string()
    } else {
        strings::value_ago(unix_now().saturating_sub(handshake))
    }
}

// The rows for a tunnel, from what the service and the login page said
pub fn details(tunnel: &Tunnel) -> Details {
    let info = &tunnel.info;
    let mut details = Details::default();

    details.group(GROUP_CONNECTION, strings::GROUP_CONNECTION);
    details.row(strings::DETAIL_STATUS, sentence(&tunnel.describe()));
    if info.up {
        details.row(strings::DETAIL_SINCE, time::format_local(info.since));
        details.row(strings::DETAIL_HANDSHAKE, handshake_text(info.handshake));
        details.row(strings::DETAIL_RECEIVED, strings::value_bytes(info.rx_bytes));
        details.row(strings::DETAIL_SENT, strings::value_bytes(info.tx_bytes));
    }

    let routes: Vec<IpNet> = info.routes.iter().filter_map(|route| IpNet::parse(route)).collect();
    details.group(GROUP_ROUTING, strings::GROUP_ROUTING);
    details.row(strings::DETAIL_MODE, routing_text(routing(&routes)));
    for route in &routes {
        details.row(route.to_string(), route_text(route));
    }

    details.group(GROUP_COMPUTER, strings::GROUP_COMPUTER);
    details.row(strings::DETAIL_ADDRESS, list_or(&info.addresses, strings::VALUE_NONE));
    details.row(strings::DETAIL_DNS, list_or(&info.dns, strings::VALUE_DNS_NONE));
    if !info.dns_search.is_empty() {
        details.row(strings::DETAIL_DNS_SEARCH, info.dns_search.join(", "));
    }
    let mtu = match (info.mtu_in_use, info.mtu) {
        (0, 0) => strings::VALUE_AUTOMATIC.to_string(),
        (0, mtu) => mtu.to_string(),
        (in_use, 0) => strings::value_mtu_automatic(in_use),
        (in_use, _) => in_use.to_string(),
    };
    details.row(strings::DETAIL_MTU, mtu);
    let port = if info.listen_port == 0 { strings::VALUE_AUTOMATIC.to_string() } else { info.listen_port.to_string() };
    details.row(strings::DETAIL_LISTEN_PORT, port);
    if !info.public_key.is_empty() {
        details.row(strings::DETAIL_PUBLIC_KEY, &info.public_key);
    }
    if let Some(device) = &info.device {
        details.row(strings::DETAIL_DEVICE, device);
    }

    let several = info.peers.len() > 1;
    for (index, peer) in info.peers.iter().enumerate() {
        if several {
            details.group(GROUP_SERVER + index as i32, strings::group_server(index + 1, peer.name.as_deref()));
        } else {
            details.group(GROUP_SERVER, strings::GROUP_SERVER);
            if let Some(name) = &peer.name {
                details.row(strings::DETAIL_NAME, name);
            }
        }
        let (host, port) = split_endpoint(&peer.endpoint);
        details.row(strings::DETAIL_SERVER, if host.is_empty() { strings::VALUE_NONE.to_string() } else { host.clone() });
        if !port.is_empty() {
            details.row(strings::DETAIL_PORT, port);
        }
        let mut in_use = host;
        if !peer.fallbacks.is_empty() {
            details.row(strings::DETAIL_FALLBACKS, peer.fallbacks.join(", "));
            if info.up && !peer.in_use.is_empty() {
                // 0 for the main address
                let fallback = peer.fallbacks.iter().position(|fallback| *fallback == peer.in_use).map_or(0, |at| at + 1);
                details.row(strings::DETAIL_IN_USE, strings::value_in_use(&peer.in_use, fallback));
                in_use = split_endpoint(&peer.in_use).0;
            }
        }
        if info.up && !peer.address.is_empty() {
            let (address, _) = split_endpoint(&peer.address);
            if address != in_use {
                details.row(strings::DETAIL_IP_IN_USE, address);
            }
        }
        details.row(strings::DETAIL_PUBLIC_KEY, &peer.public_key);
        details.row(strings::DETAIL_PRESHARED, if peer.preshared_key { strings::VALUE_YES } else { strings::VALUE_NO });
        let keepalive =
            if peer.keepalive == 0 { strings::VALUE_OFF.to_string() } else { strings::value_keepalive(peer.keepalive) };
        details.row(strings::DETAIL_KEEPALIVE, keepalive);
        // with one server, the routing and the connection say it all
        if several {
            details.row(strings::DETAIL_ALLOWED_IPS, list_or(&peer.allowed_ips, strings::VALUE_NONE));
            if info.up {
                details.row(strings::DETAIL_HANDSHAKE, handshake_text(peer.handshake));
                details.row(strings::DETAIL_RECEIVED, strings::value_bytes(peer.rx_bytes));
                details.row(strings::DETAIL_SENT, strings::value_bytes(peer.tx_bytes));
            }
        }
    }

    details.group(GROUP_LOGIN, strings::GROUP_LOGIN);
    match &tunnel.page {
        None => details.row(strings::DETAIL_LOGIN_PAGE, strings::VALUE_NONE),
        Some(page) => {
            details.row(strings::DETAIL_LOGIN_PAGE, page.url());
            if info.up && tunnel.session == Session::LoggedIn {
                details.row(strings::DETAIL_USER, &tunnel.user);
                details.row(strings::DETAIL_SESSION_END, time::format_local(tunnel.expires));
            }
        }
    }
    details
}

pub struct DetailsWindow {
    pub hwnd: HWND,
    pub tunnel: String,
    dpi: u32,
    fonts: Fonts,
    heading: HWND,
    list: HWND,
    copy: HWND,
    close: HWND,
    shown: Details,
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
            log!("can't register the window of details: {}", crate::win::last_error_message());
        }
    });
}

fn send(window: HWND, message: u32, wparam: usize, lparam: LPARAM) -> LRESULT {
    unsafe { SendMessageW(window, message, wparam, lparam) }
}

// in the clipboard, as text
fn copy_text(owner: HWND, text: &str) -> bool {
    let data: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    // another program can have it open for a moment
    let mut attempts = 0;
    while unsafe { OpenClipboard(owner) } == 0 {
        attempts += 1;
        if attempts == 20 {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    unsafe {
        EmptyClipboard();
        let memory = GlobalAlloc(GMEM_MOVEABLE, data.len() * 2);
        let mut copied = false;
        if !memory.is_null() {
            let target = GlobalLock(memory) as *mut u16;
            if !target.is_null() {
                ptr::copy_nonoverlapping(data.as_ptr(), target, data.len());
                GlobalUnlock(memory);
                // the clipboard owns the memory once it has it
                copied = !SetClipboardData(CF_UNICODETEXT, memory as HANDLE).is_null();
            }
            if !copied {
                GlobalFree(memory);
            }
        }
        CloseClipboard();
        copied
    }
}

impl DetailsWindow {
    pub fn open(tunnel: &str, details: Details) -> Option<DetailsWindow> {
        register_class();
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
                wide(&strings::details_title(tunnel)).as_ptr(),
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
            log!("can't open the window of details: {}", crate::win::last_error_message());
            return None;
        }
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        let list_style = WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_NOCOLUMNHEADER;
        let mut window = DetailsWindow {
            hwnd,
            tunnel: tunnel.to_string(),
            dpi,
            fonts: Fonts::new(dpi),
            heading: child(hwnd, "STATIC", tunnel, SS_NOPREFIX, 0, ID_HEADING),
            list: child(hwnd, "SysListView32", "", list_style, 0, ID_LIST),
            copy: child(hwnd, "BUTTON", strings::DETAILS_COPY, WS_TABSTOP | BS_PUSHBUTTON as u32, 0, ID_COPY),
            close: child(hwnd, "BUTTON", strings::DETAILS_CLOSE, WS_TABSTOP | BS_DEFPUSHBUTTON as u32, 0, IDCANCEL),
            shown: Details::default(),
        };
        window.apply_fonts();
        let list = window.list;
        let extended = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP;
        send(list, LVM_SETEXTENDEDLISTVIEWSTYLE, extended as usize, extended as LPARAM);
        unsafe { SetWindowTheme(list, wide("Explorer").as_ptr(), ptr::null()) };
        for column in 0..2 {
            let mut info: LVCOLUMNW = unsafe { zeroed() };
            info.mask = LVCF_WIDTH;
            info.cx = scale(100, dpi);
            send(list, LVM_INSERTCOLUMNW, column, &info as *const _ as LPARAM);
        }
        send(list, LVM_ENABLEGROUPVIEW, 1, 0);
        window.update(details);
        // in the middle of the display with the mouse
        let s = |value: i32| scale(value, dpi);
        let mut rect = RECT { left: 0, top: 0, right: s(520), bottom: s(680) };
        unsafe { AdjustWindowRectExForDpi(&mut rect, STYLE, 0, EX_STYLE, dpi) };
        let width = (rect.right - rect.left).min(work.right - work.left);
        let height = (rect.bottom - rect.top).min(work.bottom - work.top);
        let x = work.left + (work.right - work.left - width) / 2;
        let y = work.top + (work.bottom - work.top - height) / 2;
        unsafe {
            SetWindowPos(hwnd, ptr::null_mut(), x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        window.layout();
        unsafe {
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
            SetFocus(list);
        }
        add_dialog(hwnd);
        Some(window)
    }

    fn apply_fonts(&self) {
        for control in [self.list, self.copy, self.close] {
            set_font(control, self.fonts.normal);
        }
        set_font(self.heading, self.fonts.heading);
    }

    pub fn layout(&self) {
        let s = |value: i32| scale(value, self.dpi);
        let mut client: RECT = unsafe { zeroed() };
        unsafe { GetClientRect(self.hwnd, &mut client) };
        let (width, height) = (client.right, client.bottom);
        let margin = s(16);
        let normal = self.fonts.normal;
        let (_, heading_height) = measure(self.hwnd, self.fonts.heading, &get_text(self.heading), None);
        place(self.heading, margin, margin, width - margin * 2, heading_height);
        let button_height = line_height(self.hwnd, normal) + s(14);
        let button_width = [strings::DETAILS_COPY, strings::DETAILS_CLOSE]
            .iter()
            .map(|text| measure(self.hwnd, normal, text, None).0 + s(32))
            .max()
            .unwrap_or(0)
            .max(s(96));
        let button_y = height - margin - button_height;
        place(self.close, width - margin - button_width, button_y, button_width, button_height);
        place(self.copy, width - margin - button_width * 2 - s(8), button_y, button_width, button_height);
        let list_y = margin + heading_height + s(10);
        place(self.list, margin, list_y, width - margin * 2, (button_y - s(12) - list_y).max(0));
        self.size_columns();
    }

    // the labels as wide as the longest one, the values in the rest
    fn size_columns(&self) {
        let s = |value: i32| scale(value, self.dpi);
        let labels = self
            .shown
            .rows
            .iter()
            .map(|row| measure(self.hwnd, self.fonts.normal, &row.label, None).0)
            .max()
            .unwrap_or(0)
            + s(36);
        let mut client: RECT = unsafe { zeroed() };
        unsafe { GetClientRect(self.list, &mut client) };
        let values = (client.right - labels - s(4)).max(s(120));
        send(self.list, LVM_SETCOLUMNWIDTH, 0, labels as LPARAM);
        send(self.list, LVM_SETCOLUMNWIDTH, 1, values as LPARAM);
    }

    fn set_cell(&self, index: usize, column: i32, text: &str) {
        let mut text = wide(text);
        let mut item: LVITEMW = unsafe { zeroed() };
        item.iSubItem = column;
        item.pszText = text.as_mut_ptr();
        send(self.list, LVM_SETITEMTEXTW, index, &item as *const _ as LPARAM);
    }

    // Only the values that changed, or all again when the rows did: the selection stays while the bytes count
    pub fn update(&mut self, details: Details) {
        if details == self.shown {
            return;
        }
        let same_rows = details.groups == self.shown.groups
            && details.rows.len() == self.shown.rows.len()
            && details.rows.iter().zip(&self.shown.rows).all(|(new, old)| new.group == old.group && new.label == old.label);
        if same_rows {
            for (index, (new, old)) in details.rows.iter().zip(&self.shown.rows).enumerate() {
                if new.value != old.value {
                    self.set_cell(index, 1, &new.value);
                }
            }
        } else {
            send(self.list, WM_SETREDRAW, 0, 0);
            send(self.list, LVM_DELETEALLITEMS, 0, 0);
            send(self.list, LVM_REMOVEALLGROUPS, 0, 0);
            for group in &details.groups {
                let mut header = wide(&group.header);
                let mut info: LVGROUP = unsafe { zeroed() };
                info.cbSize = size_of::<LVGROUP>() as u32;
                info.mask = LVGF_HEADER | LVGF_GROUPID;
                info.pszHeader = header.as_mut_ptr();
                info.iGroupId = group.id;
                send(self.list, LVM_INSERTGROUP, usize::MAX, &info as *const _ as LPARAM);
            }
            for (index, row) in details.rows.iter().enumerate() {
                let mut label = wide(&row.label);
                let mut item: LVITEMW = unsafe { zeroed() };
                item.mask = LVIF_TEXT | LVIF_GROUPID;
                item.iItem = index as i32;
                item.pszText = label.as_mut_ptr();
                item.iGroupId = row.group;
                send(self.list, LVM_INSERTITEMW, 0, &item as *const _ as LPARAM);
                self.set_cell(index, 1, &row.value);
            }
            send(self.list, WM_SETREDRAW, 1, 0);
            unsafe { InvalidateRect(self.list, ptr::null(), 1) };
        }
        self.shown = details;
        self.size_columns();
    }

    // the rows selected, or all of them
    pub fn copy(&self, selected_only: bool) {
        let text = if selected_only {
            let mut text = String::new();
            let mut index = usize::MAX;
            loop {
                let next = send(self.list, LVM_GETNEXTITEM, index, LVNI_SELECTED as LPARAM);
                let Some(row) = usize::try_from(next).ok().and_then(|next| self.shown.rows.get(next)) else { break };
                text += &format!("{}: {}\r\n", row.label, row.value);
                index = next as usize;
            }
            text
        } else {
            self.shown.text(&strings::details_title(&self.tunnel))
        };
        if !text.is_empty() && !copy_text(self.hwnd, &text) {
            log!("can't copy the details to the clipboard");
        }
    }

    pub fn select_all(&self) {
        let mut item: LVITEMW = unsafe { zeroed() };
        item.stateMask = LVIS_SELECTED;
        item.state = LVIS_SELECTED;
        send(self.list, LVM_SETITEMSTATE, usize::MAX, &item as *const _ as LPARAM);
    }

    pub fn dpi_changed(&mut self, dpi: u32, suggested: &RECT) {
        self.dpi = dpi;
        let previous = replace(&mut self.fonts, Fonts::new(dpi));
        self.apply_fonts();
        drop(previous);
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

    pub fn activate(&self) {
        unsafe {
            if IsIconic(self.hwnd) != 0 {
                ShowWindow(self.hwnd, SW_RESTORE);
            }
            SetForegroundWindow(self.hwnd);
        }
    }
}

impl Drop for DetailsWindow {
    fn drop(&mut self) {
        unsafe { DestroyWindow(self.hwnd) };
    }
}

fn low_word(value: usize) -> u32 {
    (value & 0xffff) as u32
}

unsafe extern "system" fn window_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match message {
        WM_CTLCOLORSTATIC => {
            let dc = wparam as HDC;
            SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
            SetBkColor(dc, GetSysColor(COLOR_WINDOW));
            return GetSysColorBrush(COLOR_WINDOW) as LRESULT;
        }
        // Enter closes, as Esc
        DM_GETDEFID => return ((DC_HASDEFID << 16) | IDCANCEL as u32) as LRESULT,
        WM_COMMAND => {
            match low_word(wparam) as i32 {
                IDCANCEL => {
                    with_app(|app| app.close_details(hwnd));
                }
                ID_COPY => {
                    with_app(|app| app.details_of(hwnd).map(|window| window.copy(false)));
                }
                _ => {}
            }
            return 0;
        }
        WM_NOTIFY => {
            let header = &*(lparam as *const NMHDR);
            if header.code == LVN_KEYDOWN && GetKeyState(VK_CONTROL as i32) < 0 {
                // packed in commctrl.h
                let key = ptr::addr_of!((*(lparam as *const NMLVKEYDOWN)).wVKey).read_unaligned();
                match key {
                    0x43 => {
                        with_app(|app| app.details_of(hwnd).map(|window| window.copy(true)));
                    }
                    0x41 => {
                        with_app(|app| app.details_of(hwnd).map(|window| window.select_all()));
                    }
                    _ => {}
                }
            }
            return 0;
        }
        WM_SIZE => {
            with_app(|app| app.details_of(hwnd).map(|window| window.layout()));
            return 0;
        }
        WM_GETMINMAXINFO => {
            let dpi = GetDpiForWindow(hwnd);
            let info = &mut *(lparam as *mut MINMAXINFO);
            info.ptMinTrackSize = POINT { x: scale(380, dpi), y: scale(320, dpi) };
            return 0;
        }
        WM_CLOSE => {
            with_app(|app| app.close_details(hwnd));
            return 0;
        }
        WM_DPICHANGED => {
            let suggested = *(lparam as *const RECT);
            with_app(|app| app.details_of(hwnd).map(|window| window.dpi_changed(low_word(wparam), &suggested)));
            return 0;
        }
        WM_DESTROY => remove_dialog(hwnd),
        _ => {}
    }
    DefWindowProcW(hwnd, message, wparam, lparam)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(texts: &[&str]) -> Vec<IpNet> {
        texts.iter().map(|text| IpNet::parse(text).unwrap()).collect()
    }

    #[test]
    fn full_or_split() {
        assert_eq!(routing(&nets(&["0.0.0.0/0", "::/0"])), Routing::Full);
        assert_eq!(routing(&nets(&["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"])), Routing::Full);
        assert_eq!(routing(&nets(&["0.0.0.0/0"])), Routing::FullIpv4 { ipv6: false });
        assert_eq!(routing(&nets(&["0.0.0.0/0", "fd00::/64"])), Routing::FullIpv4 { ipv6: true });
        assert_eq!(routing(&nets(&["::/0", "10.0.0.0/8"])), Routing::FullIpv6 { ipv4: true });
        assert_eq!(routing(&nets(&["10.103.1.0/24", "192.168.1.0/24"])), Routing::Split);
        // a half twice, or a half and a part of it, isn't all
        assert_eq!(routing(&nets(&["0.0.0.0/1", "0.0.0.0/1"])), Routing::Split);
        assert_eq!(routing(&nets(&["0.0.0.0/1", "10.0.0.0/8"])), Routing::Split);
        assert_eq!(routing(&nets(&["0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"])), Routing::FullIpv4 { ipv6: false });
        assert_eq!(routing(&[]), Routing::None);
    }

    #[test]
    fn texts() {
        assert_eq!(route_text(&IpNet::parse("10.103.1.0/24").unwrap()), "Mask 255.255.255.0");
        assert_eq!(route_text(&IpNet::parse("10.103.1.1/32").unwrap()), strings::VALUE_ONE_ADDRESS);
        assert_eq!(route_text(&IpNet::parse("0.0.0.0/0").unwrap()), "Default route: all the IPv4 addresses");
        assert_eq!(split_endpoint("vpn.example.com:51820"), ("vpn.example.com".into(), "51820".into()));
        assert_eq!(split_endpoint("[2001:db8::1]:51820"), ("2001:db8::1".into(), "51820".into()));
        assert_eq!(split_endpoint(""), (String::new(), String::new()));
        assert_eq!(sentence("connected as anna"), "Connected as anna");
        assert_eq!(strings::value_bytes(512), "512 bytes");
        assert_eq!(strings::value_bytes(1536), "1.5 KB");
        assert_eq!(strings::value_bytes(5 * 1024 * 1024 * 1024), "5.0 GB");
    }

    #[test]
    fn fallbacks() {
        let mut tunnel = Tunnel::new("Office");
        tunnel.info.peers = vec![crate::ipc::PeerInfo {
            endpoint: "vpn.example.com:51820".into(),
            fallbacks: vec!["203.0.113.10:51821".into(), "vpn3.example.com:51820".into()],
            ..Default::default()
        }];
        let rows = |tunnel: &Tunnel| details(tunnel).text("Office");
        // off: the addresses of the configuration
        let text = rows(&tunnel);
        assert!(text.contains("Server address: vpn.example.com\r\n"), "{}", text);
        assert!(text.contains("Fallback addresses: 203.0.113.10:51821, vpn3.example.com:51820\r\n"), "{}", text);
        assert!(!text.contains("in use"), "{}", text);

        // on, at the main address, then a fallback
        tunnel.info.up = true;
        tunnel.info.peers[0].in_use = "vpn.example.com:51820".into();
        tunnel.info.peers[0].address = "198.51.100.1:51820".into();
        let text = rows(&tunnel);
        assert!(text.contains("Address in use: vpn.example.com:51820 (main)\r\n"), "{}", text);
        assert!(text.contains("IP address in use: 198.51.100.1\r\n"), "{}", text);
        tunnel.info.peers[0].in_use = "203.0.113.10:51821".into();
        tunnel.info.peers[0].address = "203.0.113.10:51821".into();
        let text = rows(&tunnel);
        assert!(text.contains("Address in use: 203.0.113.10:51821 (fallback 1)\r\n"), "{}", text);
        assert!(!text.contains("IP address in use"), "{}", text);

        // without fallbacks, as before
        tunnel.info.peers[0].fallbacks.clear();
        let text = rows(&tunnel);
        assert!(!text.contains("Fallback") && !text.contains("Address in use"), "{}", text);
    }
}
