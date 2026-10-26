// The JSON API of the login page of ns-wgauth, reachable only through the tunnel:
//   GET  /api/status   {"authenticated", "otp_required", "server", "user", "expires", "blocked", "no_user"}
//   POST /api/login    {"username", "password", "otp"}
//   POST /api/logout
// Plain HTTP to an address of the tunnel, never through a proxy.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use serde_json::{Map, Value};

use crate::conf::{Config, IpNet};
use crate::names;

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
}

impl ApiResult {
    fn unreachable(failure: String) -> ApiResult {
        ApiResult { failure: Some(failure), ..ApiResult::default() }
    }

    // nginx answers some errors, 429 for example, with a page instead of JSON
    fn from_body(status: u16, body: &[u8], location: Option<String>) -> ApiResult {
        let data = match serde_json::from_slice::<Value>(body) {
            Ok(Value::Object(data)) => data,
            _ => Map::new(),
        };
        ApiResult { status, data, failure: None, location }
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

pub fn status(page: &Page) -> ApiResult {
    send("GET", page, "/api/status", None, REQUEST_TIMEOUT)
}

pub fn login(page: &Page, username: &str, password: &str, otp: &str) -> ApiResult {
    let body = serde_json::json!({ "username": username, "password": password, "otp": otp });
    send("POST", page, "/api/login", Some(&body), REQUEST_TIMEOUT)
}

pub fn logout(page: &Page, timeout: Option<Duration>) -> ApiResult {
    send("POST", page, "/api/logout", Some(&serde_json::json!({})), timeout.unwrap_or(REQUEST_TIMEOUT))
}

// The login page reached through one of the addresses, None if none leads to one
pub fn discover(candidates: &[Ipv4Addr], login_port: u16, web_port: u16) -> Option<Page> {
    for &host in candidates {
        // the login page on its port: it answers when the redirect is off, or the user is logged in
        let page = Page { host, port: login_port };
        if is_login_page(&page) {
            return Some(page);
        }
        // the redirect of ns-wgauth sends any web request of a peer that isn't logged in to the login page
        let web = Page { host, port: web_port };
        let answer = exchange("GET", &web, "/", None, "*/*", PROBE_TIMEOUT);
        if let Ok((status, location, _)) = answer {
            if (300..400).contains(&status) {
                if let Some(page) = location.as_deref().and_then(Page::parse) {
                    if is_login_page(&page) {
                        return Some(page);
                    }
                }
            }
        }
    }
    None
}

fn is_login_page(page: &Page) -> bool {
    let result = send("GET", page, "/api/status", None, PROBE_TIMEOUT);
    result.status == 200 && result.has("authenticated") && result.has("otp_required")
}

// Where the login page can be: the firewall gives a WireGuard server the first address of its network, and the
// peers route that network through the tunnel
pub fn candidates(config: &Config) -> Vec<Ipv4Addr> {
    candidates_of(&config.addresses, &config.routes())
}

pub fn candidates_of(addresses: &[IpNet], routes: &[IpNet]) -> Vec<Ipv4Addr> {
    let own: Vec<IpAddr> = addresses.iter().map(|net| net.addr).collect();
    let mut result: Vec<Ipv4Addr> = Vec::new();
    let mut add = |candidate: Option<Ipv4Addr>| {
        if let Some(candidate) = candidate {
            if !result.contains(&candidate) && !own.contains(&IpAddr::V4(candidate)) {
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
    // with all the traffic through the tunnel there's no such route: guess the network from the address
    for address in &own {
        add(IpNet { addr: *address, prefix: GUESSED_PREFIX }.first_host());
    }
    result.truncate(MAX_CANDIDATES);
    result
}

fn user_agent() -> String {
    format!("{}/{}", names::PRODUCT.replace(' ', "-"), names::VERSION)
}

fn send(method: &str, page: &Page, path: &str, body: Option<&Value>, timeout: Duration) -> ApiResult {
    let body = body.map(|body| body.to_string());
    match exchange(method, page, path, body.as_deref(), "application/json", timeout) {
        Ok((status, location, body)) => ApiResult::from_body(status, &body, location),
        Err(error) => ApiResult::unreachable(error.to_string()),
    }
}

// One request on its own connection, closed by the server after the answer: the status, the Location header and
// the body
fn exchange(
    method: &str,
    page: &Page,
    path: &str,
    body: Option<&str>,
    accept: &str,
    timeout: Duration,
) -> io::Result<(u16, Option<String>, Vec<u8>)> {
    let address = SocketAddr::from((page.host, page.port));
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
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
    }
}
