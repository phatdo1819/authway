// The JSON API of the login page of ns-wgauth, reachable only through the tunnel:
//   GET  /api/status   {"authenticated", "otp_required", "server", "user", "expires", "blocked", "no_user", "device"}
//        ?device=<ID>  the ID of the device key, see device.rs: with device binding, "device" says "this_device"
//   POST /api/login    {"username", "password", "otp", "device"}, "device" signed by the service, see device.rs
//   POST /api/logout
// Plain HTTP to an address of the tunnel, never through a proxy. The requests go out only through the network
// adapter of the tunnel, `interface` (its index), and only to an address of its routes: the password never goes
// another way, whatever the routes of the local network say.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use serde_json::{Map, Value};

use crate::conf::{Config, IpNet};
use crate::device::Proof;
use crate::{log, names, net};

pub const DEFAULT_PORT: u16 = 8181;
pub const WEB_PORT: u16 = 80;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESPONSE: u64 = 64 * 1024;
// the size of a VPN network of the firewall, for the peers
const GUESSED_PREFIX: u8 = 24;
const MAX_CANDIDATES: usize = 3;

// The address of a login page: http://<IPv4>:<port>/
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Page {
    pub host: Ipv4Addr,
    pub port: u16,
}

impl Page {
    // The address of a login page, None if the text isn't one: the login page refuses the requests that don't use
    // the address of the server, so a name is no good. Without a port, the one of the login page.
    pub fn parse(text: &str) -> Option<Page> {
        let text = text.trim();
        let rest = match text.find("://") {
            Some(start) if text[..start].eq_ignore_ascii_case("http") => &text[start + 3..],
            Some(_) => return None,
            None => text,
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                (host, port.parse::<u16>().ok()?)
            }
            None => (authority, 80),
        };
        let host: Ipv4Addr = host.parse().ok()?;
        if port == 0 {
            return None;
        }
        // the page is never on the port of the web: that one leads to it
        let port = if port == WEB_PORT { DEFAULT_PORT } else { port };
        Some(Page { host, port })
    }

    pub fn url(&self) -> String {
        format!("http://{}:{}/", self.host, self.port)
    }

    pub fn authority(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

impl fmt::Display for Page {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.url())
    }
}

// An answer of the login API: the HTTP status, 0 when the page can't be reached, and the JSON object
#[derive(Clone, Debug, Default)]
pub struct ApiResult {
    pub status: u16,
    pub data: Map<String, Value>,
    // why the page couldn't be reached
    pub failure: Option<String>,
    pub location: Option<String>,
    // nothing was sent, for a reason of this computer: the text for the user
    pub local_error: Option<String>,
}

impl ApiResult {
    fn unreachable(failure: String) -> ApiResult {
        ApiResult { failure: Some(failure), ..ApiResult::default() }
    }

    pub fn local(failure: &str, text: &str) -> ApiResult {
        ApiResult { failure: Some(failure.to_string()), local_error: Some(text.to_string()), ..ApiResult::default() }
    }

    // nginx answers some errors, 429 for example, with a page instead of JSON
    fn from_body(status: u16, body: &[u8], location: Option<String>) -> ApiResult {
        let data = match serde_json::from_slice::<Value>(body) {
            Ok(Value::Object(data)) => data,
            _ => Map::new(),
        };
        ApiResult { status, data, failure: None, location, local_error: None }
    }

    pub fn reached(&self) -> bool {
        self.status != 0
    }

    pub fn error(&self) -> &str {
        self.get_str("error")
    }

    pub fn has(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    pub fn get_str(&self, key: &str) -> &str {
        self.data.get(key).and_then(Value::as_str).unwrap_or("")
    }

    pub fn get_bool(&self, key: &str) -> bool {
        self.data.get(key).and_then(Value::as_bool).unwrap_or(false)
    }

    pub fn get_int(&self, key: &str, fallback: i64) -> i64 {
        self.data.get(key).and_then(Value::as_i64).unwrap_or(fallback)
    }
}

impl fmt::Display for ApiResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.reached() {
            return f.write_str(self.failure.as_deref().unwrap_or("unreachable"));
        }
        if self.error().is_empty() {
            write!(f, "HTTP {}", self.status)
        } else {
            write!(f, "HTTP {} {}", self.status, self.error())
        }
    }
}

// With the ID of the device key, empty when there's none: None when it isn't known, the page then can't say whose
// device this is
pub fn status(page: &Page, interface: u32, device: Option<&str>) -> ApiResult {
    match device.filter(|id| id.bytes().all(|byte| byte.is_ascii_hexdigit())) {
        Some(id) => send("GET", page, interface, &format!("/api/status?device={}", id), None, REQUEST_TIMEOUT),
        None => send("GET", page, interface, "/api/status", None, REQUEST_TIMEOUT),
    }
}

// Whether the status says another device is enrolled for this configuration: only a login page that knows the ID of
// the device key sent says it
pub fn other_device(status: &ApiResult) -> bool {
    let device = status.data.get("device").and_then(Value::as_object);
    let flag = |key: &str| device.and_then(|device| device.get(key)).and_then(Value::as_bool);
    flag("required") == Some(true) && flag("enrolled") == Some(true) && flag("this_device") == Some(false)
}

pub fn login(
    page: &Page,
    interface: u32,
    username: &str,
    password: &str,
    otp: &str,
    device: Option<&Proof>,
) -> ApiResult {
    let mut body = serde_json::json!({ "username": username, "password": password, "otp": otp });
    if let Some(device) = device {
        body["device"] = serde_json::to_value(device).unwrap_or_default();
    }
    send("POST", page, interface, "/api/login", Some(&body), REQUEST_TIMEOUT)
}

// What the status says of device binding: the challenge to sign and whether the machine ID is required, None when
// the server doesn't require it
pub fn device_challenge(status: &ApiResult) -> Option<(String, bool)> {
    let device = status.data.get("device").and_then(Value::as_object)?;
    if device.get("required").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let challenge = device.get("challenge").and_then(Value::as_str).unwrap_or("").to_string();
    Some((challenge, device.get("machine_id").and_then(Value::as_bool).unwrap_or(false)))
}

pub fn logout(page: &Page, interface: u32, timeout: Option<Duration>) -> ApiResult {
    let body = serde_json::json!({});
    send("POST", page, interface, "/api/logout", Some(&body), timeout.unwrap_or(REQUEST_TIMEOUT))
}

// The login page reached through one of the addresses, None if none leads to one. Only an address of the routes
// of the tunnel, the one of the redirect too: anyone could answer at another one, and get the password.
pub fn discover(
    candidates: &[Ipv4Addr],
    routes: &[IpNet],
    interface: u32,
    login_port: u16,
    web_port: u16,
) -> Option<Page> {
    for &host in candidates.iter().filter(|&&host| routed(routes, host)) {
        // the login page on its port: it answers when the redirect is off, or the user is logged in
        let page = Page { host, port: login_port };
        if is_login_page(&page, interface) {
            return Some(page);
        }
        // the redirect of ns-wgauth sends any web request of a peer that isn't logged in to the login page
        let web = Page { host, port: web_port };
        let answer = exchange("GET", &web, interface, "/", None, "*/*", PROBE_TIMEOUT);
        if let Ok((status, location, _)) = answer {
            if (300..400).contains(&status) {
                match location.as_deref().and_then(Page::parse) {
                    Some(page) if !routed(routes, page.host) => log!("{} leads to {}, out of the VPN", web, page),
                    Some(page) if is_login_page(&page, interface) => return Some(page),
                    _ => {}
                }
            }
        }
    }
    None
}

// whether the address is reached through the tunnel
pub fn routed(routes: &[IpNet], host: Ipv4Addr) -> bool {
    routes.iter().any(|route| route.contains(IpAddr::V4(host)))
}

fn is_login_page(page: &Page, interface: u32) -> bool {
    let result = send("GET", page, interface, "/api/status", None, PROBE_TIMEOUT);
    result.status == 200 && result.has("authenticated") && result.has("otp_required")
}

// Where the login page can be: the firewall gives a WireGuard server the first address of its network, and the
// peers route that network through the tunnel. Never an address out of the routes.
pub fn candidates(config: &Config) -> Vec<Ipv4Addr> {
    candidates_of(&config.addresses, &config.routes())
}

pub fn candidates_of(addresses: &[IpNet], routes: &[IpNet]) -> Vec<Ipv4Addr> {
    let own: Vec<IpAddr> = addresses.iter().map(|net| net.addr).collect();
    let mut result: Vec<Ipv4Addr> = Vec::new();
    let mut add = |candidate: Option<Ipv4Addr>| {
        if let Some(candidate) = candidate {
            let new = !result.contains(&candidate) && !own.contains(&IpAddr::V4(candidate));
            if new && routed(routes, candidate) {
                result.push(candidate);
            }
        }
    };
    for route in routes {
        if !(8..=30).contains(&route.prefix) {
            continue;
        }
        for address in &own {
            if route.contains(*address) {
                add(route.first_host());
            }
        }
    }
    // with all the traffic through the tunnel there's no such route: guess the network from the address (a guess
    // out of the routes would go to the local network)
    for address in &own {
        add(IpNet { addr: *address, prefix: GUESSED_PREFIX }.first_host());
    }
    result.truncate(MAX_CANDIDATES);
    result
}

fn user_agent() -> String {
    format!("{}/{}", names::PRODUCT.replace(' ', "-"), names::VERSION)
}

fn send(method: &str, page: &Page, interface: u32, path: &str, body: Option<&Value>, timeout: Duration) -> ApiResult {
    let body = body.map(|body| body.to_string());
    match exchange(method, page, interface, path, body.as_deref(), "application/json", timeout) {
        Ok((status, location, body)) => ApiResult::from_body(status, &body, location),
        Err(error) => ApiResult::unreachable(error.to_string()),
    }
}

// One request on its own connection through the network adapter of the tunnel, closed by the server after the
// answer: the status, the Location header and the body
fn exchange(
    method: &str,
    page: &Page,
    interface: u32,
    path: &str,
    body: Option<&str>,
    accept: &str,
    timeout: Duration,
) -> io::Result<(u16, Option<String>, Vec<u8>)> {
    let mut stream = net::connect_through(SocketAddrV4::new(page.host, page.port), interface, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let _ = stream.set_nodelay(true);
    // the login page checks that the host is the address of the server
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: {}\r\nAccept: {}\r\nConnection: close\r\n",
        method,
        path,
        page.host,
        page.port,
        user_agent(),
        accept
    );
    if let Some(body) = body {
        request += &format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len());
    }
    request += "\r\n";
    if let Some(body) = body {
        request += body;
    }
    stream.write_all(request.as_bytes())?;
    let mut data = Vec::new();
    (&mut stream).take(MAX_RESPONSE + 8192).read_to_end(&mut data)?;
    parse_response(&data)
}

fn parse_response(data: &[u8]) -> io::Result<(u16, Option<String>, Vec<u8>)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "not an HTTP answer");
    let end = data.windows(4).position(|window| window == b"\r\n\r\n").ok_or_else(invalid)?;
    let head = String::from_utf8_lossy(&data[..end]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(invalid)?;
    let mut parts = status_line.split(' ');
    if !parts.next().unwrap_or("").starts_with("HTTP/1.") {
        return Err(invalid());
    }
    let status: u16 = parts.next().and_then(|code| code.parse().ok()).ok_or_else(invalid)?;
    let mut location = None;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "location" => location = Some(value.to_string()),
            "content-length" => length = value.parse::<usize>().ok(),
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            _ => {}
        }
    }
    let mut body = data[end + 4..].to_vec();
    if chunked {
        body = dechunk(&body).ok_or_else(invalid)?;
    } else if let Some(length) = length {
        body.truncate(length);
    }
    body.truncate(MAX_RESPONSE as usize);
    Ok((status, location, body))
}

fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let end = data.windows(2).position(|window| window == b"\r\n")?;
        let size_text = String::from_utf8_lossy(&data[..end]);
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        data = &data[end + 2..];
        if size == 0 {
            return Some(body);
        }
        body.extend_from_slice(data.get(..size)?);
        data = data.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conf;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn pages() {
        let parse = |text: &str| Page::parse(text).map(|page| page.url());
        assert_eq!(parse("http://10.103.1.1:8181/").as_deref(), Some("http://10.103.1.1:8181/"));
        assert_eq!(parse(" HTTP://10.103.1.1:8181/login?x#y ").as_deref(), Some("http://10.103.1.1:8181/"));
        assert_eq!(parse("10.103.1.1").as_deref(), Some("http://10.103.1.1:8181/"));
        assert_eq!(parse("10.103.1.1:9000").as_deref(), Some("http://10.103.1.1:9000/"));
        assert_eq!(parse("http://10.103.1.1:80/").as_deref(), Some("http://10.103.1.1:8181/"));
        for bad in ["https://10.103.1.1/", "http://vpn.example.com:8181/", "http://user@10.103.1.1/", "http://10.1:8181/", "http://10.103.1.1:/", "http://10.103.1.1:0/", "ftp://10.103.1.1/", ""] {
            assert!(Page::parse(bad).is_none(), "{}", bad);
        }
        assert_eq!(Page::parse("10.103.1.1").unwrap().authority(), "http://10.103.1.1:8181");
    }

    #[test]
    fn answers() {
        let (status, location, body) =
            parse_response(b"HTTP/1.1 302 Found\r\nLocation: http://10.103.1.1:8181/\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert_eq!((status, location.as_deref(), body.len()), (302, Some("http://10.103.1.1:8181/"), 0));
        let (status, _, body) =
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n").unwrap();
        assert_eq!((status, body.as_slice()), (200, &b"{\"a\":1}"[..]));
        let (_, _, body) = parse_response(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}junk").unwrap();
        assert_eq!(body, b"{}");
        assert!(parse_response(b"SSH-2.0-OpenSSH\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n").is_err());
        let result = ApiResult::from_body(429, b"<html>Too many</html>", None);
        assert_eq!((result.status, result.error(), result.get_int("retry_after", 60)), (429, "", 60));
        let result = ApiResult::from_body(401, br#"{"error":"invalid_credentials","retry_after":30}"#, None);
        assert_eq!(result.to_string(), "HTTP 401 invalid_credentials");
        assert_eq!(result.get_int("retry_after", 60), 30);
    }

    #[test]
    fn where_the_login_page_can_be() {
        let config = |address: &str, allowed: &str| {
            let text = format!(
                "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = {}\n[Peer]\n\
                 PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = {}\nEndpoint = 192.0.2.1:51820\n",
                address, allowed
            );
            candidates(&conf::parse(&text).unwrap())
        };
        let ip = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        assert_eq!(config("10.103.1.2", "192.168.1.0/24, 10.103.1.0/24"), vec![ip("10.103.1.1")]);
        // all the traffic: the guess of a /24
        assert_eq!(config("10.103.1.2", "0.0.0.0/0, ::/0"), vec![ip("10.103.1.1")]);
        // a bigger network of the server, and the guess
        assert_eq!(config("10.8.5.2", "10.8.0.0/16"), vec![ip("10.8.0.1"), ip("10.8.5.1")]);
        // the address itself is never a candidate
        assert_eq!(config("10.103.1.1", "0.0.0.0/0"), Vec::<Ipv4Addr>::new());
        // nor a guess out of the routes: it would go to the local network
        assert_eq!(config("10.103.1.2", "192.168.1.0/24"), Vec::<Ipv4Addr>::new());
        assert_eq!(config("10.103.1.2/24", "192.168.1.0/24"), Vec::<Ipv4Addr>::new());
    }

    // A server on 127.0.0.x that gives the same answer to every request, and counts them
    fn serve(host: Ipv4Addr, answer: String) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind((host, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let counter = count.clone();
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let mut data = [0u8; 4096];
                if stream.read(&mut data).unwrap_or(0) > 0 {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = stream.write_all(answer.as_bytes());
                }
            }
        });
        (port, count)
    }

    fn reply(status: &str, headers: &str, body: &str) -> String {
        format!("HTTP/1.1 {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", status, headers, body.len(), body)
    }

    #[test]
    fn only_through_the_tunnel() {
        let loopback = net::best_interface(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let ip = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        let net = |text: &str| IpNet::parse(text).unwrap();
        // the login page on 127.0.0.2, and the redirect of the web port of 127.0.0.1 to it
        let answer = reply("200 OK", "", r#"{"authenticated":false,"otp_required":true}"#);
        let (login_port, logins) = serve(ip("127.0.0.2"), answer);
        let location = format!("Location: http://127.0.0.2:{}/\r\n", login_port);
        let (web_port, webs) = serve(ip("127.0.0.1"), reply("302 Found", &location, ""));
        let page = Page { host: ip("127.0.0.2"), port: login_port };

        // a redirect out of the routes: never followed
        let found = discover(&[ip("127.0.0.1")], &[net("127.0.0.1/32")], loopback, login_port, web_port);
        assert_eq!((found, webs.load(Ordering::SeqCst), logins.load(Ordering::SeqCst)), (None, 1, 0));
        // nor a candidate out of the routes
        assert_eq!(discover(&[ip("127.0.0.1")], &[net("10.0.0.0/8")], loopback, login_port, web_port), None);
        assert_eq!(webs.load(Ordering::SeqCst), 1);
        // in the routes
        let found = discover(&[ip("127.0.0.1")], &[net("127.0.0.0/8")], loopback, login_port, web_port);
        assert_eq!(found, Some(page));
        assert!(status(&page, loopback, None).get_bool("otp_required"));
        let before = logins.load(Ordering::SeqCst);

        // through another network adapter, or one not known yet: nothing is sent
        let internet = net::best_interface(&"192.0.2.1:0".parse().unwrap()).filter(|&index| index != loopback);
        for interface in internet.into_iter().chain([0]) {
            let result = login(&page, interface, "alice", "Secret,1234", "123456", None);
            assert!(!result.reached(), "{}: {}", interface, result);
        }
        thread::sleep(Duration::from_millis(200));
        assert_eq!(logins.load(Ordering::SeqCst), before);
    }
}
