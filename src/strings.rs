// Every text shown to the user, in one place for the translations

use crate::names::PRODUCT;

pub const STATE_OFF: &str = "not connected";
pub const STATE_CONNECTING: &str = "connecting...";
pub const STATE_DISCONNECTING: &str = "disconnecting...";
pub const STATE_FAILED: &str = "can't connect";
pub const STATE_NO_ANSWER: &str = "the server doesn't answer";
pub const STATE_UNREACHABLE: &str = "the login page doesn't answer";
pub const STATE_CONNECTED: &str = "connected";
pub const STATE_NEED_LOGIN: &str = "waiting for the login";
pub const STATE_BLOCKED: &str = "configuration blocked";
pub const STATE_NO_USER: &str = "configuration not linked to a user";
pub const STATE_NO_OTP: &str = "codes of the user not set up";
pub const STATE_NOT_ENROLLED: &str = "no device enrolled";

pub fn state_logged_in(user: &str, until: &str) -> String {
    format!("connected as {} until {}", user, until)
}

pub const MENU_CONNECT: &str = "Connect";
pub const MENU_DISCONNECT: &str = "Disconnect";
pub const MENU_LOG_IN: &str = "Log in...";
pub const MENU_IMPORT: &str = "Add a VPN from its file...";
pub const MENU_REMOVE: &str = "Remove a VPN";
pub const MENU_LOGS: &str = "Logs";
pub const MENU_APP_LOG: &str = "Log of the app";
pub const MENU_SERVICE_LOG: &str = "Log of the service";
pub const MENU_QUIT: &str = "Quit";
pub const MENU_NO_TUNNELS: &str = "No VPN yet: add the file of your administrator";
pub const MENU_SERVICE_DOWN: &str = "The VPN service isn't running";
pub const MENU_START_SERVICE: &str = "Start the VPN service";
pub const MENU_DETAILS: &str = "Details...";
pub const MENU_OPEN_AT_SIGN_IN: &str = "Open the window at sign-in";
pub const MENU_ALL_VPNS: &str = "All the VPNs";

pub fn menu_open() -> String {
    format!("Open {}", PRODUCT)
}

pub fn menu_version(version: &str) -> String {
    format!("Version {}", version)
}

pub const LOGIN_USERNAME: &str = "Username";
pub const LOGIN_PASSWORD: &str = "Password";
pub const LOGIN_REMEMBER: &str = "Remember my password on this computer";
pub const LOGIN_OTP: &str = "Code";
pub const LOGIN_OTP_CUE: &str = "6 digits";
pub const LOGIN_HINT: &str = "Enter your username and password to use the VPN.";
pub const LOGIN_HINT_OTP: &str =
    "Enter your username, your password and the code of your authenticator app to use the VPN.";
pub const LOGIN_CONNECT: &str = "Connect";
pub const LOGIN_BUSY: &str = "Connecting...";
pub const CANCEL: &str = "Cancel";
// the buttons of the questions on macOS, where they say what they do
pub const REPLACE: &str = "Replace";
pub const REMOVE: &str = "Remove";

pub fn login_connecting(server: &str) -> String {
    format!("Connecting to {}...", server)
}

// the same texts as the login page
pub const ERROR_CREDENTIALS: &str = "Wrong username, password or code.";
pub const ERROR_BLOCKED: &str = "This VPN configuration is blocked: it seems to be used on more than one device at \
                                 the same time. Contact your administrator.";
pub const ERROR_NO_USER: &str = "This VPN configuration is not linked to a user yet. Contact your administrator.";
pub const ERROR_NO_OTP: &str =
    "The one-time codes of your user are not set up. Contact your administrator for a new QR code.";
pub const ERROR_FORBIDDEN: &str = "The login page doesn't accept this VPN connection. Contact your administrator.";
pub const ERROR_UNREACHABLE: &str = "Can't reach the login page. Check your internet connection and try again.";
pub const ERROR_NO_ANSWER: &str =
    "The VPN server doesn't answer. Check your internet connection, or ask your administrator.";
pub const ERROR_FAILED: &str = "The login didn't work. Try again in a moment.";
// with device binding
pub const ERROR_NOT_ENROLLED: &str = "No device is enrolled for this VPN configuration, and a new one can't enroll. \
                                      Contact your administrator.";
pub const ERROR_DEVICE_MISMATCH: &str = "This VPN configuration is enrolled on another device: it works only there. \
                                         Contact your administrator to use it on this computer.";
pub const ERROR_DEVICE_REQUIRED: &str = "This VPN requires a login signed by the enrolled device, and this one \
                                         couldn't be signed. Try again, or contact your administrator.";
pub const NOTICE_ENROLL: &str = "Your first login enrolls this computer: then this VPN works only here.";
pub const ERROR_MISSING: &str = "Enter your username and password.";
pub const ERROR_MISSING_OTP: &str = "Enter the 6-digit code of your authenticator app.";

pub fn error_attempts(minutes: i64) -> String {
    format!("Too many failed attempts. Try again in {} min.", minutes)
}

pub fn error_connect(reason: &str) -> String {
    format!("Can't connect: {}", reason.trim_end_matches('.'))
}

pub const NOTICE_SESSION_ENDED: &str = "Your VPN session ended: log in again to keep using the VPN.";

pub fn notice_login_needed(server: &str) -> String {
    format!("Log in to {} to use the VPN.", server)
}

pub fn notice_connected(server: &str) -> String {
    format!("Connected to {}.", server)
}

pub fn notice_logged_in(server: &str, user: &str, until: &str) -> String {
    format!("Connected to {} as {} until {}.", server, user, until)
}

pub fn notice_disconnected(server: &str) -> String {
    format!("Disconnected from {}.", server)
}

pub fn notice_failed(server: &str, reason: &str) -> String {
    format!("Can't connect to {}: {}", server, reason)
}

// where the icon of the app is
#[cfg(windows)]
const PLACE: &str = "next to the clock";
#[cfg(not(windows))]
const PLACE: &str = "in the menu bar";
#[cfg(windows)]
const OPEN_MENU: &str = "right-click the icon";
#[cfg(not(windows))]
const OPEN_MENU: &str = "click the icon";
// how the system asks for an administrator
#[cfg(windows)]
const ADMIN_PROMPT: &str = "Windows will ask for the permission.";
#[cfg(not(windows))]
const ADMIN_PROMPT: &str = "macOS will ask for the name and password of an administrator.";

pub fn notice_welcome() -> String {
    format!("{} is {}. Add your VPN from the file of your administrator: {}.", PRODUCT, PLACE, OPEN_MENU)
}

pub fn notice_running() -> String {
    format!("{} is running, {}.", PRODUCT, PLACE)
}

pub const IMPORT_TITLE: &str = "Add a VPN";
pub const IMPORT_FILTER: &str = "VPN configuration (*.conf)|*.conf|All files (*.*)|*.*";

pub fn import_needs_admin() -> String {
    format!("Only an administrator can add a VPN on this computer. {}", ADMIN_PROMPT)
}
pub const IMPORT_SAVED: &str =
    "The configuration is saved on this computer, protected: only the VPN service can read its keys.";
pub const IMPORT_CONNECT: &str = "Connect now";
pub const IMPORT_LATER: &str = "Close";

pub fn import_invalid(error: &str) -> String {
    format!("This file isn't a VPN configuration that can be used:\n\n{}", error)
}

pub fn import_unreadable(error: &str) -> String {
    format!("Can't read the file: {}", error)
}

pub fn import_exists(name: &str) -> String {
    format!("There's already a VPN named {}. Replace it with this file?", name)
}

pub fn import_ready(name: &str) -> String {
    format!("{} is ready", name)
}

pub fn import_delete_file(file: &str) -> String {
    format!("Delete the file {}: it isn't needed anymore", file)
}

// --import with --username and --password
pub const IMPORT_LOGIN_NO_PAGE: &str = "This configuration has no login page (no \"# Login =\" line), so there's no \
                                        login to save: leave out --username and --password.";
pub const IMPORT_LOGIN_NO_REMEMBER: &str = "The policy RememberPassword = 0 of this computer doesn't let the app save \
                                            passwords: leave out --password, the username alone can be saved.";
pub const IMPORT_LOGIN_SYSTEM: &str = "The username and password are saved for the account that runs this command, \
                                       and this one is the system's, not a user's: run it as the user of the VPN, \
                                       who's asked for an administrator when needed.";

pub fn import_login_not_saved(name: &str, store: &str) -> String {
    format!("{} is added, but its login couldn't be saved in {}.", name, store)
}

pub fn remove_confirm(name: &str) -> String {
    format!("Remove the VPN {} from this computer? You'll need its file to add it again.", name)
}

pub fn remove_needs_admin() -> String {
    format!("Only an administrator can remove a VPN from this computer. {}", ADMIN_PROMPT)
}

pub fn rename_failed(error: &str) -> String {
    format!("Can't rename the VPN:\n\n{}", error)
}

pub fn quit_confirm() -> String {
    format!("Disconnect the VPN and quit {}?", PRODUCT)
}

pub fn service_unavailable() -> String {
    format!("The VPN service of {} isn't running. Start it from the menu {}, or ask your administrator.", PRODUCT, PLACE)
}

#[cfg(windows)]
pub fn not_installed() -> String {
    format!(
        "{} isn't installed on this computer. Install it with its .msi file: Windows asks for the permission of an \
         administrator, once.",
        PRODUCT
    )
}

#[cfg(not(windows))]
pub fn not_installed() -> String {
    format!(
        "{} isn't installed on this Mac. Install it with its .pkg file: macOS asks for the password of an \
         administrator, once.",
        PRODUCT
    )
}

// the window of details
pub fn details_title(name: &str) -> String {
    format!("Details of {}", name)
}

pub const DETAILS_COPY: &str = "Copy all";
pub const DETAILS_CLOSE: &str = "Close";

pub const GROUP_CONNECTION: &str = "Connection";
pub const GROUP_ROUTING: &str = "Routing";
pub const GROUP_COMPUTER: &str = "This computer";
pub const GROUP_SERVER: &str = "Server";
pub const GROUP_LOGIN: &str = "Login";

pub fn group_server(number: usize, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("Server {}: {}", number, name),
        None => format!("Server {}", number),
    }
}

pub const DETAIL_STATUS: &str = "Status";
pub const DETAIL_SINCE: &str = "Connected since";
pub const DETAIL_HANDSHAKE: &str = "Last handshake";
pub const DETAIL_RECEIVED: &str = "Received";
pub const DETAIL_SENT: &str = "Sent";
pub const DETAIL_MODE: &str = "Mode";
pub const DETAIL_BEFORE_LOGIN: &str = "Before the login";
pub const DETAIL_ADDRESS: &str = "Address";
pub const DETAIL_DNS: &str = "DNS servers";
pub const DETAIL_DNS_SEARCH: &str = "DNS search domains";
pub const DETAIL_MTU: &str = "MTU";
pub const DETAIL_LISTEN_PORT: &str = "Listen port";
pub const DETAIL_PUBLIC_KEY: &str = "Public key";
pub const DETAIL_DEVICE: &str = "Name on the server";
pub const DETAIL_NAME: &str = "Name";
pub const DETAIL_SERVER: &str = "Server address";
pub const DETAIL_PORT: &str = "Port";
pub const DETAIL_FALLBACKS: &str = "Fallback addresses";
pub const DETAIL_IN_USE: &str = "Address in use";
pub const DETAIL_IP_IN_USE: &str = "IP address in use";
pub const DETAIL_PRESHARED: &str = "Preshared key";
pub const DETAIL_ALLOWED_IPS: &str = "Allowed IPs";
pub const DETAIL_KEEPALIVE: &str = "Keepalive";
pub const DETAIL_LOGIN_PAGE: &str = "Login page";
pub const DETAIL_USER: &str = "Logged in as";
pub const DETAIL_SESSION_END: &str = "Session ends";

pub const VALUE_AUTOMATIC: &str = "Automatic";
pub const VALUE_NONE: &str = "None";
pub const VALUE_YES: &str = "Yes";
pub const VALUE_NO: &str = "No";
pub const VALUE_OFF: &str = "Off";
pub const VALUE_NOT_YET: &str = "Not yet";
pub const VALUE_DNS_NONE: &str = "None: the ones of the network of the computer";
pub const VALUE_ONE_ADDRESS: &str = "One address";
pub const VALUE_IPV6_NETWORK: &str = "IPv6 network";
pub const VALUE_BEFORE_LOGIN: &str = "Only the login page and the private networks";

pub fn value_dns_after_login(servers: &str) -> String {
    format!("{} (after the login)", servers)
}

pub fn value_keepalive(seconds: u16) -> String {
    format!("Every {} seconds", seconds)
}

// 0 for the address of the server, then 1 for its first fallback...
pub fn value_in_use(endpoint: &str, fallback: usize) -> String {
    match fallback {
        0 => format!("{} (main)", endpoint),
        _ => format!("{} (fallback {})", endpoint, fallback),
    }
}

pub fn value_mtu_automatic(mtu: u32) -> String {
    format!("{} (automatic)", mtu)
}

pub fn value_ago(seconds: u64) -> String {
    match seconds {
        0..=1 => "Just now".to_string(),
        2..=119 => format!("{} seconds ago", seconds),
        _ => format!("{} minutes ago", seconds / 60),
    }
}

pub fn value_bytes(count: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if count < 1024 {
        return format!("{} bytes", count);
    }
    let mut value = count as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.1} {}", value, UNITS[unit])
}

pub fn value_mask(mask: &str) -> String {
    format!("Mask {}", mask)
}

pub fn value_default_route(ipv6: bool) -> String {
    format!("Default route: all the {} addresses", if ipv6 { "IPv6" } else { "IPv4" })
}

// the main window, where the system has one
pub const HOME_ADD: &str = "Add VPN";
pub const HOME_MORE: &str = "More";
pub const HOME_BACK: &str = "Back";
pub const HOME_EMPTY_TITLE: &str = "No VPN yet";
pub const HOME_EMPTY_TEXT: &str = "Add the .conf file that your administrator gave you, or drop it on this window.";
pub const HOME_EMPTY_ADD: &str = "Add a VPN from its file";
pub const HOME_START_SERVICE: &str = "Start it";
pub const HOME_LOG_IN: &str = "Log in";
pub const HOME_DROP: &str = "Drop the file to add the VPN";
pub const HOME_TRAFFIC: &str = "Traffic";
pub const HOME_TRAFFIC_OFF: &str = "Connect to see the traffic of this VPN.";
pub const HOME_DOWNLOAD: &str = "Download";
pub const HOME_UPLOAD: &str = "Upload";
pub const HOME_DURATION: &str = "Connected for";
pub const HOME_ADDRESS: &str = "Address in the VPN";
pub const HOME_SERVER: &str = "Server";
pub const HOME_ROUTING: &str = "Routing";
pub const HOME_ROUTING_FULL: &str = "All the traffic goes through the VPN.";
pub const HOME_ROUTING_NONE: &str = "No traffic goes through the VPN.";
pub const HOME_ROUTING_BEFORE_LOGIN: &str =
    "Until you log in, the internet goes through your own connection, not through the VPN.";
pub const HOME_SETTINGS: &str = "Settings";
pub const HOME_NAME: &str = "Name";
pub const HOME_RENAME_OFF: &str = "Disconnect the VPN to rename it.";
pub const HOME_USERNAME: &str = "Username";
pub const HOME_PASSWORD_SAVED: &str = "Your password is saved on this computer.";
pub const HOME_PASSWORD_NOT_SAVED: &str = "Your password isn't saved: the login asks for it.";
pub const HOME_NO_LOGIN: &str = "This VPN has no login: the file is all it needs.";
pub const HOME_FORGET: &str = "Forget it";
pub const HOME_SAVE: &str = "Save changes";
pub const HOME_ALL_DETAILS: &str = "All details";
pub const HOME_REMOVE: &str = "Remove this VPN";

pub fn home_routing_split(networks: &str) -> String {
    format!("Only these networks go through the VPN: {}.", networks)
}

// all of one version of IP; the networks of the other one, if any
pub fn home_routing_full_one(full: &str, other: &str, networks: Option<&str>) -> String {
    match networks {
        Some(networks) => format!("All the {} traffic goes through the VPN, and the {} networks {}.", full, other, networks),
        None => format!("All the {} traffic goes through the VPN, not the {} traffic.", full, other),
    }
}

// a change of username leaves the password of the other one behind
pub fn home_username_changed(saved: &str) -> String {
    format!("Saving forgets the password saved for {}.", saved)
}

// the name of a switch, for the screen readers
pub fn home_switch(name: &str, on: bool) -> String {
    format!("{} {}", if on { MENU_DISCONNECT } else { MENU_CONNECT }, name)
}

pub fn notice_still_running() -> String {
    format!("{} keeps running {}: open it from its icon, or quit it from its menu.", PRODUCT, PLACE)
}

pub fn value_rate(bytes_per_second: f64) -> String {
    if bytes_per_second < 1024.0 {
        return format!("{:.0} B/s", bytes_per_second);
    }
    let mut value = bytes_per_second / 1024.0;
    let mut unit = "KB/s";
    for next in ["MB/s", "GB/s"] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{:.1} {}", value, unit)
}

// 12:34, or 1:02:03
pub fn value_duration(seconds: u64) -> String {
    let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    if hours > 0 {
        format!("{}:{:02}:{:02}", hours, minutes, seconds)
    } else {
        format!("{}:{:02}", minutes, seconds)
    }
}

// what goes through the VPN
pub const ROUTING_FULL: &str = "Full tunnel: all the traffic";
pub const ROUTING_SPLIT: &str = "Split tunnel: only the networks below";
pub const ROUTING_NONE: &str = "No route: no traffic";

// full for one version of IP: the other one only to its networks below, or not at all
pub fn routing_full_one(full: &str, other: &str, other_routed: bool) -> String {
    if other_routed {
        format!("Full tunnel for {}, {} only to the networks below", full, other)
    } else {
        format!("Full tunnel for {}, no {}", full, other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(value_rate(0.0), "0 B/s");
        assert_eq!(value_rate(1000.0), "1000 B/s");
        assert_eq!(value_rate(1536.0), "1.5 KB/s");
        assert_eq!(value_rate(3.5 * 1024.0 * 1024.0), "3.5 MB/s");
        assert_eq!(value_duration(0), "0:00");
        assert_eq!(value_duration(754), "12:34");
        assert_eq!(value_duration(3723), "1:02:03");
    }
}
