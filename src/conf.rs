// The WireGuard configuration files, as the firewall writes them for its peers:
//
//   [Interface]
//   # Name = Alice laptop
//   # Login = http://10.103.1.1:8181/
//   PrivateKey = ...
//   Address = 10.103.1.2
//   DNS = 10.103.1.1
//
//   [Peer]
//   # Name = Road warriors
//   PublicKey = ...
//   AllowedIPs = 10.103.1.0/24, 192.168.1.0/24
//   Endpoint = vpn.example.com:51820
//   # Fallback = vpn2.example.com:51820, 203.0.113.10:51821
//   PersistentKeepalive = 25

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type Key = [u8; 32];

pub const MAX_NAME_LENGTH: usize = 32;

// An address with the length of its prefix: 10.103.1.0/24
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    // "10.0.0.0/24", or an address alone for a single host
    pub fn parse(text: &str) -> Option<IpNet> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address.trim(), Some(prefix.trim())),
            None => (text.trim(), None),
        };
        let addr: IpAddr = address.parse().ok()?;
        let max = max_prefix(addr);
        let prefix = match prefix {
            Some(text) => {
                if text.is_empty() || text.len() > 3 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                text.parse().ok()?
            }
            None => max,
        };
        if prefix > max {
            return None;
        }
        Some(IpNet { addr, prefix })
    }

    pub fn is_host(&self) -> bool {
        self.prefix == max_prefix(self.addr)
    }

    // without the bits of the host: 10.103.1.0/24 for 10.103.1.2/24
    pub fn network(&self) -> IpNet {
        IpNet { addr: masked(self.addr, self.prefix), prefix: self.prefix }
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        addr.is_ipv4() == self.addr.is_ipv4() && masked(addr, self.prefix) == masked(self.addr, self.prefix)
    }

    // the first address of an IPv4 network, the one the firewall gives to a WireGuard server
    pub fn first_host(&self) -> Option<Ipv4Addr> {
        match self.addr {
            IpAddr::V4(addr) if self.prefix <= 30 => {
                Some(Ipv4Addr::from(u32::from(masked_v4(addr, self.prefix)).wrapping_add(1)))
            }
            _ => None,
        }
    }

    // all of it in a network that the internet doesn't route
    pub fn is_private(&self) -> bool {
        PRIVATE_NETWORKS.iter().any(|range| self.prefix >= range.prefix && range.contains(self.addr))
    }
}

// the private networks of IPv4, the shared one of the providers (RFC 6598), the link-local ones and the unique
// local addresses of IPv6
const PRIVATE_NETWORKS: [IpNet; 7] = [
    IpNet { addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), prefix: 8 },
    IpNet { addr: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), prefix: 12 },
    IpNet { addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), prefix: 16 },
    IpNet { addr: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), prefix: 10 },
    IpNet { addr: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), prefix: 16 },
    IpNet { addr: IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), prefix: 7 },
    IpNet { addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), prefix: 10 },
];

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() {
        32
    } else {
        128
    }
}

fn masked_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
    Ipv4Addr::from(u32::from(addr) & mask)
}

fn masked(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => IpAddr::V4(masked_v4(addr, prefix.min(32))),
        IpAddr::V6(addr) => {
            let prefix = prefix.min(128) as u32;
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            IpAddr::V6(Ipv6Addr::from(u128::from(addr) & mask))
        }
    }
}

// The server of a peer: a name or an address, and the UDP port
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    // "vpn.example.com:51820", "203.0.113.1:51820", "[2001:db8::1]:51820"
    pub fn parse(text: &str) -> Option<Endpoint> {
        let text = text.trim();
        let (host, port) = match text.strip_prefix('[') {
            Some(rest) => {
                let (host, port) = rest.split_once("]:")?;
                host.parse::<Ipv6Addr>().ok()?;
                (host, port)
            }
            None => {
                let (host, port) = text.rsplit_once(':')?;
                // an IPv6 address needs its brackets
                if host.contains(':') {
                    return None;
                }
                (host, port)
            }
        };
        let valid_host = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':');
        if host.is_empty() || host.len() > 253 || !host.chars().all(valid_host) {
            return None;
        }
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let port: u16 = port.parse().ok()?;
        if port == 0 {
            return None;
        }
        Some(Endpoint { host: host.to_string(), port })
    }

    // also "host", "[2001:db8::1]" or "2001:db8::1" alone, with the port given
    pub fn parse_or_port(text: &str, port: u16) -> Option<Endpoint> {
        let text = text.trim();
        Endpoint::parse(text).or_else(|| {
            let host = if text.contains(':') && !text.starts_with('[') { format!("[{}]", text) } else { text.to_string() };
            Endpoint::parse(&format!("{}:{}", host, port))
        })
    }

    pub fn same_as(&self, other: &Endpoint) -> bool {
        self.port == other.port && self.host.eq_ignore_ascii_case(&other.host)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<Endpoint>,
    // "# Fallback = ...": the other addresses of the server, tried when it doesn't answer at the Endpoint; never
    // the Endpoint again, and none without it
    pub fallbacks: Vec<Endpoint>,
    // seconds, 0 when off
    pub keepalive: u16,
    // "# Name = ...": the name of the server
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub private_key: Key,
    // 0 for any
    pub listen_port: u16,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub mtu: Option<u16>,
    pub peers: Vec<Peer>,
    // "# Name = ...": the name of this device on the firewall
    pub name: Option<String>,
    // "# Login = ...": the login page, when the server requires a login
    pub login: Option<String>,
    // the options of wg-quick that do nothing here, scripts included: they never run
    pub ignored: Vec<String>,
}

impl Config {
    // the name of the server, for the window titles
    pub fn server_name(&self) -> Option<&str> {
        self.peers.iter().find_map(|peer| peer.name.as_deref())
    }

    pub fn routes(&self) -> Vec<IpNet> {
        let mut routes: Vec<IpNet> = Vec::new();
        for net in self.peers.iter().flat_map(|peer| peer.allowed_ips.iter()) {
            let net = net.network();
            if !routes.contains(&net) {
                routes.push(net);
            }
        }
        routes
    }

    // whether the address is reached through the tunnel
    pub fn routes_to(&self, addr: IpAddr) -> bool {
        self.peers.iter().flat_map(|peer| peer.allowed_ips.iter()).any(|net| net.contains(addr))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    // 0 for the file as a whole
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.line > 0 {
            write!(f, "line {}: {}", self.line, self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

fn error<T>(line: usize, message: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError { line, message: message.into() })
}

// A key of WireGuard in base64: 44 characters for 32 bytes
pub fn parse_key(text: &str) -> Option<Key> {
    let bytes = text.trim().as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return None;
    }
    let mut key = [0u8; 32];
    let mut buffer: u32 = 0;
    let mut bits = 0;
    let mut count = 0;
    for &c in &bytes[..43] {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if count < key.len() {
                key[count] = (buffer >> bits) as u8;
            }
            count += 1;
            buffer &= (1 << bits) - 1;
        }
    }
    // 43 characters carry 258 bits: the last 2 are zero
    if count != 32 || buffer != 0 {
        return None;
    }
    Some(key)
}

pub fn encode_key(key: &Key) -> String {
    base64(key)
}

// Standard base64, with padding
pub fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bytes = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let value = (bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32;
        for i in 0..=chunk.len() {
            text.push(ALPHABET[(value >> (18 - 6 * i) & 63) as usize] as char);
        }
        for _ in chunk.len()..3 {
            text.push('=');
        }
    }
    text
}

fn values(text: &str) -> impl Iterator<Item = &str> {
    text.split(',').map(str::trim).filter(|item| !item.is_empty())
}

fn is_domain(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && text.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
        })
}

// the options of wg-quick and of other apps that don't apply here
const IGNORED_INTERFACE: &[&str] = &["table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark"];

#[derive(Default)]
struct PeerDraft {
    line: usize,
    public_key: Option<Key>,
    preshared_key: Option<Key>,
    allowed_ips: Vec<IpNet>,
    endpoint: Option<Endpoint>,
    fallbacks: Vec<String>,
    keepalive: u16,
    name: Option<String>,
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

pub fn parse(text: &str) -> Result<Config, ParseError> {
    let mut section = Section::None;
    let mut interface_line = 0;
    let mut private_key = None;
    let mut listen_port = 0;
    let mut addresses = Vec::new();
    let mut dns = Vec::new();
    let mut dns_search = Vec::new();
    let mut mtu = None;
    let mut name = None;
    let mut login = None;
    let mut ignored = Vec::new();
    let mut peers: Vec<PeerDraft> = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim_start_matches('\u{feff}').trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            // the comments of the firewall: "# Name = ...", "# Login = ...", "# Fallback = ..."
            if let Some((key, value)) = comment.split_once('=') {
                let value = value.trim();
                if !value.is_empty() {
                    match (&section, key.trim().to_ascii_lowercase().as_str()) {
                        (Section::Interface, "name") => name = Some(value.to_string()),
                        (Section::Interface, "login") => login = Some(value.to_string()),
                        (Section::Peer, "name") => {
                            if let Some(peer) = peers.last_mut() {
                                peer.name = Some(value.to_string());
                            }
                        }
                        (Section::Peer, "fallback") => {
                            if let Some(peer) = peers.last_mut() {
                                peer.fallbacks.extend(values(value).map(str::to_string));
                            }
                        }
                        _ => {}
                    }
                }
            }
            continue;
        }
        let line = match line.find('#') {
            Some(start) => line[..start].trim(),
            None => line,
        };
        if line.starts_with('[') {
            match line.to_ascii_lowercase().as_str() {
                "[interface]" => {
                    if interface_line > 0 {
                        return error(number, "there's a second [Interface] section");
                    }
                    interface_line = number;
                    section = Section::Interface;
                }
                "[peer]" => {
                    peers.push(PeerDraft { line: number, ..PeerDraft::default() });
                    section = Section::Peer;
                }
                _ => return error(number, format!("{} isn't a section of WireGuard", line)),
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return error(number, "this line isn't \"Option = value\"");
        };
        let key = key.trim();
        let value = value.trim();
        let lower = key.to_ascii_lowercase();
        match section {
            Section::None => return error(number, "the file doesn't start with [Interface]"),
            Section::Interface => match lower.as_str() {
                "privatekey" => match parse_key(value) {
                    Some(key) => private_key = Some(key),
                    None => return error(number, "PrivateKey isn't a valid key"),
                },
                "listenport" => match value.parse() {
                    Ok(port) => listen_port = port,
                    Err(_) => return error(number, "ListenPort isn't a valid port"),
                },
                "address" => {
                    for item in values(value) {
                        match IpNet::parse(item) {
                            Some(net) => addresses.push(net),
                            None => return error(number, format!("{} isn't a valid address", item)),
                        }
                    }
                }
                "dns" => {
                    for item in values(value) {
                        if let Ok(addr) = item.parse::<IpAddr>() {
                            dns.push(addr);
                        } else if is_domain(item) {
                            dns_search.push(item.to_string());
                        } else {
                            return error(number, format!("{} isn't a valid DNS server or domain", item));
                        }
                    }
                }
                "mtu" => match value.parse::<u16>() {
                    Ok(value) if value >= 576 => mtu = Some(value),
                    _ => return error(number, "MTU isn't a number from 576 to 65535"),
                },
                _ if IGNORED_INTERFACE.contains(&lower.as_str()) => ignored.push(key.to_string()),
                _ => return error(number, format!("{} isn't an option of [Interface]", key)),
            },
            Section::Peer => {
                let peer = peers.last_mut().expect("a [Peer] section");
                match lower.as_str() {
                    "publickey" => match parse_key(value) {
                        Some(key) => peer.public_key = Some(key),
                        None => return error(number, "PublicKey isn't a valid key"),
                    },
                    "presharedkey" => match parse_key(value) {
                        Some(key) => peer.preshared_key = Some(key),
                        None => return error(number, "PresharedKey isn't a valid key"),
                    },
                    "allowedips" => {
                        for item in values(value) {
                            match IpNet::parse(item) {
                                Some(net) => peer.allowed_ips.push(net),
                                None => return error(number, format!("{} isn't a valid network", item)),
                            }
                        }
                    }
                    "endpoint" => match Endpoint::parse(value) {
                        Some(endpoint) => peer.endpoint = Some(endpoint),
                        None => return error(number, "Endpoint isn't \"host:port\""),
                    },
                    "persistentkeepalive" => {
                        if value.eq_ignore_ascii_case("off") {
                            peer.keepalive = 0;
                        } else {
                            match value.parse() {
                                Ok(seconds) => peer.keepalive = seconds,
                                Err(_) => return error(number, "PersistentKeepalive isn't a number of seconds"),
                            }
                        }
                    }
                    _ => return error(number, format!("{} isn't an option of [Peer]", key)),
                }
            }
        }
    }

    if interface_line == 0 {
        return error(0, "there's no [Interface] section");
    }
    let Some(private_key) = private_key else {
        return error(interface_line, "[Interface] has no PrivateKey");
    };
    if addresses.is_empty() {
        return error(interface_line, "[Interface] has no Address");
    }
    if peers.is_empty() {
        return error(0, "there's no [Peer] section");
    }
    let mut result = Vec::with_capacity(peers.len());
    for draft in peers {
        let Some(public_key) = draft.public_key else {
            return error(draft.line, "this [Peer] has no PublicKey");
        };
        if result.iter().any(|peer: &Peer| peer.public_key == public_key) {
            return error(draft.line, "this [Peer] has the same PublicKey as another one");
        }
        // a comment: what isn't valid is left out, as the other apps leave out all of it
        let mut fallbacks: Vec<Endpoint> = Vec::new();
        if let Some(endpoint) = &draft.endpoint {
            for text in &draft.fallbacks {
                match Endpoint::parse_or_port(text, endpoint.port) {
                    Some(fallback) => {
                        if !fallback.same_as(endpoint) && !fallbacks.iter().any(|other| other.same_as(&fallback)) {
                            fallbacks.push(fallback);
                        }
                    }
                    None => ignored.push(format!("Fallback {}", text)),
                }
            }
        }
        result.push(Peer {
            public_key,
            preshared_key: draft.preshared_key,
            allowed_ips: draft.allowed_ips,
            endpoint: draft.endpoint,
            fallbacks,
            keepalive: draft.keepalive,
            name: draft.name,
        });
    }
    if !result.iter().any(|peer| peer.endpoint.is_some()) {
        return error(0, "no [Peer] has an Endpoint: the computer wouldn't know where the server is");
    }
    Ok(Config {
        private_key,
        listen_port,
        addresses,
        dns,
        dns_search,
        mtu,
        peers: result,
        name,
        login,
        ignored,
    })
}

// The name of a tunnel, also the name of its network adapter and of its key in the registry
pub fn is_valid_name(name: &str) -> bool {
    let length = name.chars().count();
    (1..=MAX_NAME_LENGTH).contains(&length)
        && name.chars().all(|c| c.is_ascii_alphanumeric() || " _=+.-".contains(c))
        && !name.starts_with([' ', '.'])
        && !name.ends_with([' ', '.'])
}

// A valid name made from a text, the name of the server for example
pub fn name_from(text: &str) -> String {
    let mut name = String::new();
    for c in text.trim().chars() {
        let c = if c.is_ascii_alphanumeric() || " _=+.-".contains(c) { c } else { '-' };
        // no runs of separators
        if (c == '-' || c == ' ') && name.ends_with(['-', ' ']) {
            continue;
        }
        name.push(c);
        if name.chars().count() >= MAX_NAME_LENGTH {
            break;
        }
    }
    let name = name.trim_matches(|c: char| c == ' ' || c == '.' || c == '-').to_string();
    if is_valid_name(&name) {
        name
    } else {
        "VPN".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUBLIC: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const PRESHARED: &str = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

    fn nethsecurity() -> String {
        format!(
            "[Interface]\n# Name = Alice laptop\n# Login = http://10.103.1.1:8181/\nPrivateKey = {}\n\
             Address = 10.103.1.2\nMTU = 1400\nDNS = 10.103.1.1,example.lan\n\n[Peer]\n# Name = Road warriors\n\
             PublicKey = {}\nPresharedKey = {}\nAllowedIPs = 192.168.1.0/24,10.103.1.0/24\n\
             Endpoint = vpn.example.com:51820\nPersistentKeepalive = 25\n",
            PRIVATE, PUBLIC, PRESHARED
        )
    }

    #[test]
    fn keys() {
        let key = parse_key(PRIVATE).unwrap();
        assert_eq!(encode_key(&key), PRIVATE);
        assert_eq!(encode_key(&[0; 32]), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert!(parse_key("AAAA").is_none());
        // a different last character carries bits beyond the 32 bytes
        assert!(parse_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=").is_none());
        assert!(parse_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA*=").is_none());
    }

    #[test]
    fn the_configuration_of_the_firewall() {
        let config = parse(&nethsecurity()).unwrap();
        assert_eq!(config.private_key, parse_key(PRIVATE).unwrap());
        assert_eq!(config.name.as_deref(), Some("Alice laptop"));
        assert_eq!(config.login.as_deref(), Some("http://10.103.1.1:8181/"));
        assert_eq!(config.addresses, vec![IpNet::parse("10.103.1.2/32").unwrap()]);
        assert_eq!(config.mtu, Some(1400));
        assert_eq!(config.dns, vec!["10.103.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(config.dns_search, vec!["example.lan"]);
        assert_eq!(config.peers.len(), 1);
        let peer = &config.peers[0];
        assert_eq!(peer.name.as_deref(), Some("Road warriors"));
        assert_eq!(config.server_name(), Some("Road warriors"));
        assert_eq!(peer.public_key, parse_key(PUBLIC).unwrap());
        assert_eq!(peer.preshared_key, parse_key(PRESHARED));
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(peer.endpoint, Some(Endpoint { host: "vpn.example.com".into(), port: 51820 }));
        assert_eq!(peer.keepalive, 25);
        assert!(config.routes_to("10.103.1.1".parse().unwrap()));
        assert!(!config.routes_to("10.103.2.1".parse().unwrap()));
    }

    #[test]
    fn windows_files() {
        // with a byte order mark, CRLF and comments at the end of the lines
        let text = format!("\u{feff}{}", nethsecurity().replace('\n', "\r\n").replace("MTU = 1400", "MTU = 1400 # small"));
        let config = parse(&text).unwrap();
        assert_eq!(config.mtu, Some(1400));
        assert_eq!(config.login.as_deref(), Some("http://10.103.1.1:8181/"));
    }

    #[test]
    fn all_the_traffic() {
        let text = nethsecurity().replace("192.168.1.0/24,10.103.1.0/24", "0.0.0.0/0, ::/0");
        let config = parse(&text).unwrap();
        assert_eq!(config.routes().len(), 2);
        assert!(config.routes_to("8.8.8.8".parse().unwrap()));
        assert!(config.routes_to("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn fallbacks() {
        let endpoint = "Endpoint = vpn.example.com:51820\n";
        let with = |line: &str| nethsecurity().replace(endpoint, &format!("{}{}\n", endpoint, line));
        let texts = |config: &Config| config.peers[0].fallbacks.iter().map(ToString::to_string).collect::<Vec<_>>();

        // as the firewall writes them
        let config = parse(&with("# Fallback = vpn2.example.com:51820, 203.0.113.10:51821")).unwrap();
        assert_eq!(texts(&config), ["vpn2.example.com:51820", "203.0.113.10:51821"]);
        assert!(config.ignored.is_empty());
        assert!(parse(&nethsecurity()).unwrap().peers[0].fallbacks.is_empty());

        // by hand: the port of the Endpoint when missing, IPv6, the Endpoint and the doubles left out, two lines
        let config = parse(&with(
            "#Fallback=203.0.113.10, [2001:db8::10], 2001:db8::11\n# fallback = VPN.example.com:51820, 203.0.113.10:51820",
        ))
        .unwrap();
        assert_eq!(texts(&config), ["203.0.113.10:51820", "[2001:db8::10]:51820", "[2001:db8::11]:51820"]);

        // what isn't valid is left out, the rest of the file is good
        let config = parse(&with("# Fallback = a b:1, 203.0.113.10:0, , vpn3.example.com:443")).unwrap();
        assert_eq!(texts(&config), ["vpn3.example.com:443"]);
        assert_eq!(config.ignored, ["Fallback a b:1", "Fallback 203.0.113.10:0"]);

        // before the Endpoint too, but never for a server without one, nor in [Interface]
        let text = nethsecurity().replace(endpoint, &format!("# Fallback = 203.0.113.10\n{}", endpoint));
        assert_eq!(texts(&parse(&text).unwrap()), ["203.0.113.10:51820"]);
        let text = format!("{}\n[Peer]\n# Fallback = 203.0.113.10:1\nPublicKey = {}\n", nethsecurity(), PRESHARED);
        assert!(parse(&text).unwrap().peers[1].fallbacks.is_empty());
        let text = nethsecurity().replace("# Name = Alice laptop", "# Fallback = 203.0.113.10:1");
        assert!(parse(&text).unwrap().peers[0].fallbacks.is_empty());
    }

    #[test]
    fn scripts_never_run() {
        let text = nethsecurity().replace("MTU = 1400", "PostUp = calc.exe\nTable = off");
        let config = parse(&text).unwrap();
        assert_eq!(config.ignored, vec!["PostUp", "Table"]);
    }

    #[test]
    fn errors() {
        let check = |text: String, line: usize, start: &str| {
            let error = parse(&text).unwrap_err();
            assert_eq!(error.line, line, "{}", error);
            assert!(error.message.starts_with(start), "{}", error);
        };
        let good = nethsecurity();
        check(good.replace(PRIVATE, "secret"), 4, "PrivateKey isn't");
        check(good.replace("Address = 10.103.1.2", "Address = 10.103.1.300"), 5, "10.103.1.300 isn't");
        check(good.replace("Address = 10.103.1.2\n", ""), 1, "[Interface] has no Address");
        check(good.replace("MTU = 1400", "MTU = 100"), 6, "MTU isn't");
        check(good.replace("MTU = 1400", "Jc = 4"), 6, "Jc isn't an option");
        check(good.replace("Endpoint = vpn.example.com:51820", "Endpoint = vpn.example.com"), 14, "Endpoint isn't");
        check(good.replace("Endpoint = vpn.example.com:51820\n", ""), 0, "no [Peer] has an Endpoint");
        check(good.replace(&format!("PublicKey = {}\n", PUBLIC), ""), 9, "this [Peer] has no PublicKey");
        check(good.replace("[Peer]", "[Pear]"), 9, "[Pear] isn't");
        check(format!("{}\n[Interface]\n", good), 17, "there's a second");
        check(format!("PrivateKey = {}\n", PRIVATE), 1, "the file doesn't start");
        check(String::new(), 0, "there's no [Interface]");
        check(good.split("[Peer]").next().unwrap().to_string(), 0, "there's no [Peer]");
        let twice = format!("{}\n[Peer]\nPublicKey = {}\nEndpoint = 192.0.2.1:51820\n", good, PUBLIC);
        check(twice, 17, "this [Peer] has the same");
    }

    #[test]
    fn networks() {
        let net = IpNet::parse("10.103.1.2/24").unwrap();
        assert_eq!(net.network().to_string(), "10.103.1.0/24");
        assert_eq!(net.first_host(), Some("10.103.1.1".parse().unwrap()));
        assert!(net.contains("10.103.1.200".parse().unwrap()));
        assert!(!net.contains("10.103.2.1".parse().unwrap()));
        assert!(IpNet::parse("10.103.1.2").unwrap().is_host());
        assert_eq!(IpNet::parse("0.0.0.0/0").unwrap().first_host(), Some("0.0.0.1".parse().unwrap()));
        assert_eq!(IpNet::parse("10.0.0.1/31").unwrap().first_host(), None);
        assert!(IpNet::parse("::/0").unwrap().contains("2001:db8::1".parse().unwrap()));
        assert!(!IpNet::parse("::/0").unwrap().contains("10.0.0.1".parse().unwrap()));
        assert_eq!(IpNet::parse("fd00::5/64").unwrap().network().to_string(), "fd00::/64");
        let private = |text: &str| IpNet::parse(text).unwrap().is_private();
        for text in ["10.103.1.0/24", "172.31.0.0/16", "192.168.1.5", "100.64.0.0/10", "fd00::/64", "fe80::/64"] {
            assert!(private(text), "{}", text);
        }
        // the internet, or more than a private network
        for text in ["0.0.0.0/0", "::/0", "0.0.0.0/1", "8.8.8.8", "172.32.0.0/16", "10.0.0.0/7", "2001:db8::/32"] {
            assert!(!private(text), "{}", text);
        }
        for bad in ["10.0.0.1/33", "10.0.0.1/", "10.0.0.1/-1", "10.0.0/24", "::1/129", "name/24"] {
            assert!(IpNet::parse(bad).is_none(), "{}", bad);
        }
    }

    #[test]
    fn endpoints() {
        let parse = |text: &str| Endpoint::parse(text).map(|endpoint| endpoint.to_string());
        assert_eq!(parse("vpn.example.com:51820").as_deref(), Some("vpn.example.com:51820"));
        assert_eq!(parse("203.0.113.1:1").as_deref(), Some("203.0.113.1:1"));
        assert_eq!(parse("[2001:db8::1]:51820").as_deref(), Some("[2001:db8::1]:51820"));
        for bad in ["2001:db8::1:51820", "host:0", "host:65536", "host", ":51820", "a b:1", "[name]:1", "host:+1"] {
            assert!(parse(bad).is_none(), "{}", bad);
        }
    }

    #[test]
    fn names() {
        assert!(is_valid_name("Road warriors"));
        assert!(is_valid_name("office-1.vpn"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name(" office"));
        assert!(!is_valid_name("office."));
        assert!(!is_valid_name("a\\b"));
        assert!(!is_valid_name(&"x".repeat(33)));
        assert_eq!(name_from("Road warriors"), "Road warriors");
        assert_eq!(name_from("  Ufficio d'Italia / Roma "), "Ufficio d-Italia Roma");
        assert_eq!(name_from("peer-alice.conf"), "peer-alice.conf");
        assert_eq!(name_from("???"), "VPN");
        assert_eq!(name_from(&"x".repeat(40)).len(), 32);
    }
}
