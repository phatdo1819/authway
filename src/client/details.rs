// What the window of the details of a VPN shows, as the details of a network connection: its state, its routes
// (all the traffic, or only some networks), its configuration without the keys that are secret, and its login.
// Each system draws the rows its own way, and follows the tunnel every second.

use std::net::{IpAddr, Ipv4Addr};

use super::{Session, Tunnel};
use crate::conf::IpNet;
use crate::strings;
use crate::time::{self, unix_now};

// the end of a line in the text copied, as the system wants it
pub const NEWLINE: &str = if cfg!(windows) { "\r\n" } else { "\n" };

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
        let mut text = format!("{}{}", title, NEWLINE);
        for group in &self.groups {
            text += &format!("{}{}{}", NEWLINE, group.header, NEWLINE);
            for row in self.rows.iter().filter(|row| row.group == group.id) {
                text += &format!("  {}: {}{}", row.label, row.value, NEWLINE);
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
pub(crate) fn split_endpoint(endpoint: &str) -> (String, String) {
    match endpoint.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {
            (host.trim_start_matches('[').trim_end_matches(']').to_string(), port.to_string())
        }
        _ => (endpoint.to_string(), String::new()),
    }
}

pub(crate) fn sentence(text: &str) -> String {
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

pub(crate) fn handshake_text(handshake: u64) -> String {
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
    if !info.after_login.is_empty() {
        details.row(strings::DETAIL_BEFORE_LOGIN, strings::VALUE_BEFORE_LOGIN);
    }
    for route in &routes {
        details.row(route.to_string(), route_text(route));
    }

    details.group(GROUP_COMPUTER, strings::GROUP_COMPUTER);
    details.row(strings::DETAIL_ADDRESS, list_or(&info.addresses, strings::VALUE_NONE));
    // the service sets the ones of a tunnel with a login page only with the login
    let dns = match (&info.login, info.dns.is_empty()) {
        (Some(_), false) => strings::value_dns_after_login(&info.dns.join(", ")),
        _ => list_or(&info.dns, strings::VALUE_DNS_NONE),
    };
    details.row(strings::DETAIL_DNS, dns);
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
        let line = |text: &str| format!("{}{}", text, NEWLINE);
        // off: the addresses of the configuration
        let text = rows(&tunnel);
        assert!(text.contains(&line("Server address: vpn.example.com")), "{}", text);
        assert!(text.contains(&line("Fallback addresses: 203.0.113.10:51821, vpn3.example.com:51820")), "{}", text);
        assert!(!text.contains("in use"), "{}", text);

        // on, at the main address, then a fallback
        tunnel.info.up = true;
        tunnel.info.peers[0].in_use = "vpn.example.com:51820".into();
        tunnel.info.peers[0].address = "198.51.100.1:51820".into();
        let text = rows(&tunnel);
        assert!(text.contains(&line("Address in use: vpn.example.com:51820 (main)")), "{}", text);
        assert!(text.contains(&line("IP address in use: 198.51.100.1")), "{}", text);
        tunnel.info.peers[0].in_use = "203.0.113.10:51821".into();
        tunnel.info.peers[0].address = "203.0.113.10:51821".into();
        let text = rows(&tunnel);
        assert!(text.contains(&line("Address in use: 203.0.113.10:51821 (fallback 1)")), "{}", text);
        assert!(!text.contains("IP address in use"), "{}", text);

        // without fallbacks, as before
        tunnel.info.peers[0].fallbacks.clear();
        let text = rows(&tunnel);
        assert!(!text.contains("Fallback") && !text.contains("Address in use"), "{}", text);
    }
}
