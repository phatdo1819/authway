// What a tunnel changes on Linux, in plain functions tested on every system: the arguments of ip, wg and resolvectl,
// the configuration that wg takes, and what their outputs and the files of the system say. linux/net.rs and
// linux/wg.rs run them, as the WireGuard tools of Linux (wg-quick) do.

use std::net::{IpAddr, SocketAddr};

use crate::conf::{self, Config, IpNet, Key};
use crate::manager::PeerStats;
use crate::plan::{Action, Gateway, Way};

// the first line of the /etc/resolv.conf that the service writes
pub const RESOLV_MARK: &str = "# Written by Authway";
// glibc reads 3 servers at most
const MAX_NAMESERVERS: usize = 3;
// the placeholder of many boards, the same on all of them
const PLACEHOLDER_UUID: &str = "03000200-0400-0500-0006-000700080009";

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

fn family(address: IpAddr) -> &'static str {
    if address.is_ipv4() {
        "-4"
    } else {
        "-6"
    }
}

// ip link add dev authway0 type wireguard: an interface of the WireGuard of the kernel
pub fn link_add_args(interface: &str) -> Vec<String> {
    strings(&["link", "add", "dev", interface, "type", "wireguard"])
}

pub fn link_delete_args(interface: &str) -> Vec<String> {
    strings(&["link", "delete", "dev", interface])
}

pub fn link_up_args(interface: &str, mtu: u32) -> Vec<String> {
    strings(&["link", "set", "dev", interface, "mtu", &mtu.to_string(), "up"])
}

// ip -o link show type wireguard: the WireGuard interfaces, one a line
pub fn link_list_args() -> Vec<String> {
    strings(&["-o", "link", "show", "type", "wireguard"])
}

// "5: authway0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 ...": the names
pub fn parse_link_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split(": ").nth(1))
        .map(|name| name.split('@').next().unwrap_or(name).trim().to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

// the first name free of the prefix and a number, 15 characters at most
pub fn free_interface(prefix: &str, taken: &[String]) -> Option<String> {
    (0..100).map(|number| format!("{}{}", prefix, number)).find(|name| name.len() <= 15 && !taken.contains(name))
}

// ip -4 address add 10.103.1.2/24 dev authway0
pub fn address_args(interface: &str, net: &IpNet) -> Vec<String> {
    strings(&[family(net.addr), "address", "add", &net.to_string(), "dev", interface])
}

// A route of the tunnel: replaced, so it's the tunnel's even when another one was there
pub fn route_args(action: Action, net: &IpNet, interface: &str) -> Vec<String> {
    let verb = if action == Action::Add { "replace" } else { "delete" };
    strings(&[family(net.addr), "route", verb, &net.network().to_string(), "dev", interface])
}

// The address of a server through the network, never through the tunnel that carries it: ip -4 route replace
// 203.0.113.1/32 via 192.168.1.1 dev wlp2s0
pub fn host_route_args(action: Action, address: IpAddr, gateway: &Gateway) -> Vec<String> {
    let verb = if action == Action::Add { "replace" } else { "delete" };
    let host = IpNet { addr: address, prefix: if address.is_ipv4() { 32 } else { 128 } };
    let mut args = strings(&[family(address), "route", verb, &host.to_string()]);
    if let Some(router) = &gateway.address {
        args.extend(strings(&["via", router]));
    }
    args.extend(strings(&["dev", &gateway.interface]));
    args
}

pub fn route_get_args(address: IpAddr) -> Vec<String> {
    strings(&[family(address), "route", "get", &address.to_string()])
}

// "203.0.113.1 via 192.168.1.1 dev wlp2s0 src 192.168.1.10 uid 1000": through a router, or on the link of an
// interface; None for an address that can't be reached
pub fn parse_route_get(text: &str) -> Option<Way> {
    let words: Vec<&str> = text.split_whitespace().collect();
    if matches!(words.first(), Some(&("unreachable" | "prohibit" | "blackhole" | "throw"))) {
        return None;
    }
    let after = |key: &str| words.iter().position(|word| *word == key).and_then(|index| words.get(index + 1)).map(|word| word.to_string());
    let interface = after("dev")?;
    Some(match after("via") {
        Some(router) => Way::Gateway(Gateway { address: Some(router), interface }),
        None => Way::Local(interface),
    })
}

// The way to a server out of the tunnel: the one of the routes for its address, so that a server on a network of the
// computer (a virtual machine, a firewall of the office) stays on that network and isn't sent to the router; the
// default route of the network when that way goes into a tunnel
pub fn server_way(route: Option<Way>, default: Option<&Gateway>, tunnels: &str) -> Option<Way> {
    match route {
        Some(way) if !way.interface().starts_with(tunnels) && way.interface() != "lo" => Some(way),
        _ => default.cloned().map(Way::Gateway),
    }
}

pub fn default_route_args(ipv6: bool) -> Vec<String> {
    strings(&[if ipv6 { "-6" } else { "-4" }, "route", "show", "default"])
}

// "default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600": the one of the lowest metric, out of the tunnels
pub fn parse_default_route(text: &str, tunnels: &str) -> Option<Gateway> {
    let mut found: Vec<(u32, Gateway)> = Vec::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.first() != Some(&"default") {
            continue;
        }
        let after = |key: &str| words.iter().position(|word| *word == key).and_then(|index| words.get(index + 1)).copied();
        let Some(interface) = after("dev") else { continue };
        if interface.starts_with(tunnels) {
            continue;
        }
        let metric = after("metric").and_then(|metric| metric.parse().ok()).unwrap_or(0);
        found.push((metric, Gateway { address: after("via").map(str::to_string), interface: interface.to_string() }));
    }
    found.sort_by_key(|(metric, _)| *metric);
    found.into_iter().next().map(|(_, gateway)| gateway)
}

// The configuration for wg setconf, read from its standard input: never on a command line. It holds the private
// key: the caller wipes it once sent.
pub fn wg_config(config: &Config, endpoints: &[Option<SocketAddr>]) -> String {
    let mut text = format!("[Interface]\nPrivateKey = {}\n", conf::encode_key(&config.private_key));
    if config.listen_port != 0 {
        text += &format!("ListenPort = {}\n", config.listen_port);
    }
    for (index, peer) in config.peers.iter().enumerate() {
        text += &format!("\n[Peer]\nPublicKey = {}\n", conf::encode_key(&peer.public_key));
        if let Some(key) = &peer.preshared_key {
            text += &format!("PresharedKey = {}\n", conf::encode_key(key));
        }
        if let Some(Some(address)) = endpoints.get(index) {
            text += &format!("Endpoint = {}\n", address);
        }
        if peer.keepalive != 0 {
            text += &format!("PersistentKeepalive = {}\n", peer.keepalive);
        }
        if !peer.allowed_ips.is_empty() {
            let nets: Vec<String> = peer.allowed_ips.iter().map(|net| net.network().to_string()).collect();
            text += &format!("AllowedIPs = {}\n", nets.join(", "));
        }
    }
    text
}

pub fn wg_setconf_args(interface: &str) -> Vec<String> {
    strings(&["setconf", interface, "/dev/stdin"])
}

// the private key from the standard input too
pub fn wg_private_key_args(interface: &str) -> Vec<String> {
    strings(&["set", interface, "private-key", "/dev/stdin"])
}

pub fn wg_endpoint_args(interface: &str, public_key: &Key, address: &SocketAddr) -> Vec<String> {
    strings(&["set", interface, "peer", &conf::encode_key(public_key), "endpoint", &address.to_string()])
}

pub fn wg_dump_args(interface: &str) -> Vec<String> {
    strings(&["show", interface, "dump"])
}

// wg show <interface> dump: the interface on the first line, its private key with it, then a line a peer, with tabs:
// public key, preshared key, endpoint, allowed IPs, latest handshake, received, sent, keepalive
pub fn parse_dump(text: &str) -> Result<Vec<PeerStats>, String> {
    let mut lines = text.lines();
    if lines.next().is_none_or(|line| line.split('\t').count() < 4) {
        return Err("not the state of a WireGuard interface".into());
    }
    let mut peers = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 8 {
            return Err("not the state of a WireGuard interface".into());
        }
        let Some(public_key) = conf::parse_key(fields[0]) else { continue };
        let number = |text: &str| text.parse::<u64>().unwrap_or(0);
        peers.push(PeerStats {
            public_key,
            endpoint: fields[2].parse().ok(),
            last_handshake: number(fields[4]),
            rx_bytes: number(fields[5]),
            tx_bytes: number(fields[6]),
        });
    }
    Ok(peers)
}

// resolvectl, when systemd-resolved answers for the computer: the DNS servers of the interface, for every name (~.)
pub fn resolvectl_dns_args(interface: &str, servers: &[String]) -> Vec<String> {
    let mut args = strings(&["dns", interface]);
    args.extend(servers.iter().cloned());
    args
}

pub fn resolvectl_domain_args(interface: &str, search: &[String]) -> Vec<String> {
    let mut args = strings(&["domain", interface, "~."]);
    args.extend(search.iter().cloned());
    args
}

pub fn resolvectl_default_route_args(interface: &str) -> Vec<String> {
    strings(&["default-route", interface, "yes"])
}

pub fn resolvectl_revert_args(interface: &str) -> Vec<String> {
    strings(&["revert", interface])
}

// /etc/resolv.conf sends the names to systemd-resolved, on 127.0.0.53
pub fn uses_resolved(resolv_conf: &str) -> bool {
    resolv_conf.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.next() == Some("nameserver") && matches!(words.next(), Some("127.0.0.53" | "127.0.0.54"))
    })
}

// /etc/resolv.conf with the DNS servers of the tunnel, on a computer without systemd-resolved
pub fn resolv_conf(servers: &[String], search: &[String]) -> String {
    let mut text = format!("{}: the DNS servers of the VPN, the ones of before come back when it's off\n", RESOLV_MARK);
    for server in servers.iter().take(MAX_NAMESERVERS) {
        text += &format!("nameserver {}\n", server);
    }
    if !search.is_empty() {
        text += &format!("search {}\n", search.join(" "));
    }
    text
}

pub fn is_ours(resolv_conf: &str) -> bool {
    resolv_conf.starts_with(RESOLV_MARK)
}

// /etc/authway/policy.conf, of the administrator: "Name = value" lines, # for comments. True or false, 1 or 0, yes
// or no; None when the name isn't there
pub fn policy(text: &str, name: &str) -> Option<bool> {
    text.lines().rev().find_map(|line| {
        let line = line.split('#').next().unwrap_or("").trim();
        let (key, value) = line.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case(name) {
            return None;
        }
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Some(true),
            "0" | "false" | "no" => Some(false),
            _ => None,
        }
    })
}

// /sys/class/dmi/id/product_uuid, the SMBIOS UUID as the kernel writes it: in lower case, None for a placeholder
pub fn product_uuid(text: &str) -> Option<String> {
    let value = text.trim().to_lowercase();
    let valid = value.len() == 36 && value.chars().all(|char| char.is_ascii_hexdigit() || char == '-');
    let digits: String = value.chars().filter(char::is_ascii_hexdigit).collect();
    let placeholder = digits.chars().all(|char| char == '0') || digits.chars().all(|char| char == 'f');
    (valid && !placeholder && value != PLACEHOLDER_UUID).then_some(value)
}

// /etc/machine-id: 32 hexadecimal digits, made at the installation of the system
pub fn machine_id(text: &str) -> Option<String> {
    let value = text.trim().to_lowercase();
    (value.len() == 32 && value.chars().all(|char| char.is_ascii_hexdigit()) && value.chars().any(|char| char != '0'))
        .then_some(value)
}

// The MTU of an interface, from /sys/class/net/<name>/mtu
pub fn parse_mtu(text: &str) -> Option<u32> {
    text.trim().parse().ok().filter(|&mtu| mtu > 0)
}

// pkexec ends with 126 when the user closed its window, 127 when they aren't allowed or the password was wrong
pub fn pkexec_cancelled(code: Option<i32>) -> bool {
    code == Some(126)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUBLIC: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const PRESHARED: &str = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    #[test]
    fn interfaces() {
        assert_eq!(link_add_args("authway0"), ["link", "add", "dev", "authway0", "type", "wireguard"]);
        assert_eq!(link_up_args("authway0", 1420), ["link", "set", "dev", "authway0", "mtu", "1420", "up"]);
        let list = "4: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT\n\
                    7: authway0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT\n";
        let names = parse_link_names(list);
        assert_eq!(names, ["wg0", "authway0"]);
        assert_eq!(free_interface("authway", &names).as_deref(), Some("authway1"));
        assert_eq!(free_interface("authway", &[]).as_deref(), Some("authway0"));
        assert!(parse_link_names("").is_empty());
    }

    #[test]
    fn addresses_and_routes() {
        assert_eq!(address_args("authway0", &net("10.103.1.2/24")), ["-4", "address", "add", "10.103.1.2/24", "dev", "authway0"]);
        assert_eq!(address_args("authway0", &net("fd00::2/64"))[0], "-6");
        // the network, without the bits of the host
        assert_eq!(
            route_args(Action::Add, &net("10.103.1.7/24"), "authway0"),
            ["-4", "route", "replace", "10.103.1.0/24", "dev", "authway0"]
        );
        assert_eq!(route_args(Action::Delete, &net("::/1"), "authway0")[..3], ["-6", "route", "delete"]);
        let router = Gateway { address: Some("192.168.1.1".into()), interface: "wlp2s0".into() };
        assert_eq!(
            host_route_args(Action::Add, "203.0.113.1".parse().unwrap(), &router),
            ["-4", "route", "replace", "203.0.113.1/32", "via", "192.168.1.1", "dev", "wlp2s0"]
        );
        let link = Gateway { address: None, interface: "ppp0".into() };
        assert_eq!(
            host_route_args(Action::Delete, "2001:db8::1".parse().unwrap(), &link),
            ["-6", "route", "delete", "2001:db8::1/128", "dev", "ppp0"]
        );
    }

    #[test]
    fn the_way_to_an_address() {
        let router = "203.0.113.1 via 192.168.1.1 dev wlp2s0 src 192.168.1.10 uid 1000 \n    cache \n";
        assert_eq!(
            parse_route_get(router),
            Some(Way::Gateway(Gateway { address: Some("192.168.1.1".into()), interface: "wlp2s0".into() }))
        );
        assert_eq!(parse_route_get("192.168.1.20 dev wlp2s0 src 192.168.1.10 uid 1000\n"), Some(Way::Local("wlp2s0".into())));
        assert_eq!(parse_route_get("local 127.0.0.1 dev lo src 127.0.0.1 uid 1000\n"), Some(Way::Local("lo".into())));
        assert_eq!(parse_route_get("unreachable 10.9.9.9 uid 1000\n"), None);
        assert_eq!(parse_route_get(""), None);
        let defaults = "default via 10.0.0.1 dev wwan0 proto dhcp metric 700\n\
                        default via 192.168.1.1 dev wlp2s0 proto dhcp src 192.168.1.10 metric 600\n\
                        default dev authway0 scope link\n";
        assert_eq!(
            parse_default_route(defaults, "authway"),
            Some(Gateway { address: Some("192.168.1.1".into()), interface: "wlp2s0".into() })
        );
        assert_eq!(parse_default_route("default dev ppp0 scope link\n", "authway").unwrap().address, None);
        assert_eq!(parse_default_route("10.0.0.0/8 dev eth0\n", "authway"), None);
        // a server on the network stays there; one the tunnel would carry goes to the router of the network
        let router = Gateway { address: Some("192.168.1.1".into()), interface: "wlp2s0".into() };
        let local = Some(Way::Local("eth0".into()));
        assert_eq!(server_way(local.clone(), Some(&router), "authway"), local);
        let tunnel = Some(Way::Local("authway0".into()));
        assert_eq!(server_way(tunnel, Some(&router), "authway"), Some(Way::Gateway(router.clone())));
        assert_eq!(server_way(None, None, "authway"), None);
    }

    #[test]
    fn the_configuration_for_wg() {
        let text = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.103.1.2/24\nListenPort = 51900\n[Peer]\nPublicKey = {}\n\
             PresharedKey = {}\nAllowedIPs = 10.103.1.7/24, 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n\
             PersistentKeepalive = 25\n[Peer]\nPublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=\n\
             AllowedIPs = 192.168.5.0/24\n",
            PRIVATE, PUBLIC, PRESHARED
        );
        let config = conf::parse(&text).unwrap();
        let endpoints = [Some("203.0.113.1:51820".parse().unwrap()), None];
        let expected = format!(
            "[Interface]\nPrivateKey = {}\nListenPort = 51900\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\n\
             Endpoint = 203.0.113.1:51820\nPersistentKeepalive = 25\nAllowedIPs = 10.103.1.0/24, 0.0.0.0/0\n\n\
             [Peer]\nPublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=\nAllowedIPs = 192.168.5.0/24\n",
            PRIVATE, PUBLIC, PRESHARED
        );
        assert_eq!(wg_config(&config, &endpoints), expected);
        // the keys never on a command line
        assert_eq!(wg_setconf_args("authway0"), ["setconf", "authway0", "/dev/stdin"]);
        assert_eq!(wg_private_key_args("authway0"), ["set", "authway0", "private-key", "/dev/stdin"]);
        let key = conf::parse_key(PUBLIC).unwrap();
        assert_eq!(
            wg_endpoint_args("authway0", &key, &"[2001:db8::1]:51820".parse().unwrap()),
            ["set", "authway0", "peer", PUBLIC, "endpoint", "[2001:db8::1]:51820"]
        );
    }

    #[test]
    fn the_state_from_wg() {
        let dump = format!(
            "{}\t{}\t51900\toff\n{}\t{}\t203.0.113.1:51820\t10.103.1.0/24\t1767225600\t92\t148\t25\n\
             TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=\t(none)\t(none)\t192.168.5.0/24\t0\t0\t0\toff\n",
            PRIVATE, PUBLIC, PUBLIC, PRESHARED
        );
        let peers = parse_dump(&dump).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].public_key, conf::parse_key(PUBLIC).unwrap());
        assert_eq!(peers[0].endpoint, Some("203.0.113.1:51820".parse().unwrap()));
        assert_eq!((peers[0].last_handshake, peers[0].rx_bytes, peers[0].tx_bytes), (1_767_225_600, 92, 148));
        assert_eq!((peers[1].endpoint, peers[1].last_handshake), (None, 0));
        assert!(parse_dump("").is_err());
        assert!(parse_dump("garbage").is_err());
        assert!(parse_dump(&format!("{}\t{}\t0\toff\nshort\tline\n", PRIVATE, PUBLIC)).is_err());
    }

    #[test]
    fn dns() {
        let servers = vec!["10.103.1.1".to_string(), "10.103.1.2".to_string()];
        let search = vec!["corp.example".to_string()];
        assert_eq!(resolvectl_dns_args("authway0", &servers), ["dns", "authway0", "10.103.1.1", "10.103.1.2"]);
        assert_eq!(resolvectl_domain_args("authway0", &search), ["domain", "authway0", "~.", "corp.example"]);
        assert_eq!(resolvectl_domain_args("authway0", &[]), ["domain", "authway0", "~."]);
        assert!(uses_resolved("# This is /run/systemd/resolve/stub-resolv.conf\nnameserver 127.0.0.53\noptions edns0\n"));
        assert!(!uses_resolved("# Generated by NetworkManager\nnameserver 192.168.1.1\n"));
        let four: Vec<String> = (1..=4).map(|last| format!("10.0.0.{}", last)).collect();
        let text = resolv_conf(&four, &search);
        assert!(is_ours(&text));
        assert_eq!(text.lines().filter(|line| line.starts_with("nameserver")).count(), 3);
        assert!(text.ends_with("nameserver 10.0.0.3\nsearch corp.example\n"));
        assert!(!is_ours("nameserver 192.168.1.1\n"));
    }

    #[test]
    fn policies() {
        let text = "# who can add VPNs\nAllowUserImport = 1\nRememberPassword=false # never\n";
        assert_eq!(policy(text, "AllowUserImport"), Some(true));
        assert_eq!(policy(text, "allowuserimport"), Some(true));
        assert_eq!(policy(text, "RememberPassword"), Some(false));
        assert_eq!(policy(text, "Other"), None);
        // the last line wins, a value that isn't one is no value
        assert_eq!(policy("AllowUserImport = 1\nAllowUserImport = no\n", "AllowUserImport"), Some(false));
        assert_eq!(policy("AllowUserImport = maybe\n", "AllowUserImport"), None);
        assert_eq!(policy("# AllowUserImport = 1\n", "AllowUserImport"), None);
    }

    #[test]
    fn ids_of_the_computer() {
        assert_eq!(product_uuid("4C4C4544-0042-3510-8051-B4C04F4C4D32\n").as_deref(), Some("4c4c4544-0042-3510-8051-b4c04f4c4d32"));
        assert_eq!(product_uuid("00000000-0000-0000-0000-000000000000"), None);
        assert_eq!(product_uuid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"), None);
        assert_eq!(product_uuid(PLACEHOLDER_UUID), None);
        assert_eq!(product_uuid("not a uuid"), None);
        assert_eq!(machine_id("3F2A9C0D1E4B5A6978C1D2E3F4A5B6C7\n").as_deref(), Some("3f2a9c0d1e4b5a6978c1d2e3f4a5b6c7"));
        assert_eq!(machine_id("uninitialized\n"), None);
        assert_eq!(parse_mtu("1500\n"), Some(1500));
        assert_eq!(parse_mtu("0"), None);
        assert!(pkexec_cancelled(Some(126)) && !pkexec_cancelled(Some(127)) && !pkexec_cancelled(None));
    }
}
