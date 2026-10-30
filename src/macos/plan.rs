// What a tunnel changes in the network of macOS, as wg-quick does it there, in plain functions tested on every
// system: the arguments of ifconfig, route and networksetup, and what their outputs say. macos/net.rs runs them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::conf::IpNet;

// "add" or "delete" a route
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Add,
    Delete,
}

impl Action {
    fn word(self) -> &'static str {
        match self {
            Action::Add => "add",
            Action::Delete => "delete",
        }
    }
}

// The routes of the tunnel as macOS gets them: a default route becomes its two halves, which win over the default
// route of the network without replacing it, as wg-quick does
pub fn tunnel_routes(routes: &[IpNet]) -> Vec<IpNet> {
    let mut result: Vec<IpNet> = Vec::new();
    let mut add = |net: IpNet| {
        if !result.contains(&net) {
            result.push(net);
        }
    };
    for net in routes {
        match (net.prefix, net.addr) {
            (0, IpAddr::V4(_)) => {
                add(IpNet { addr: Ipv4Addr::new(0, 0, 0, 0).into(), prefix: 1 });
                add(IpNet { addr: Ipv4Addr::new(128, 0, 0, 0).into(), prefix: 1 });
            }
            (0, IpAddr::V6(_)) => {
                add(IpNet { addr: Ipv6Addr::UNSPECIFIED.into(), prefix: 1 });
                add(IpNet { addr: Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0).into(), prefix: 1 });
            }
            _ => add(net.network()),
        }
    }
    result
}

fn family(addr: IpAddr) -> &'static str {
    if addr.is_ipv4() {
        "-inet"
    } else {
        "-inet6"
    }
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

// ifconfig utun5 inet 10.103.1.2/24 10.103.1.2 alias, or inet6 fd00::2/64 alias
pub fn address_args(interface: &str, net: &IpNet) -> Vec<String> {
    let address = net.to_string();
    match net.addr {
        IpAddr::V4(addr) => strings(&[interface, "inet", &address, &addr.to_string(), "alias"]),
        IpAddr::V6(_) => strings(&[interface, "inet6", &address, "alias"]),
    }
}

// route -q -n add -inet 10.103.1.0/24 -interface utun5
pub fn route_args(action: Action, net: &IpNet, interface: &str) -> Vec<String> {
    strings(&["-q", "-n", action.word(), family(net.addr), &net.to_string(), "-interface", interface])
}

// Where the traffic goes when it's not in the tunnel: the router of the network, as route writes it (fe80::1%en0
// keeps its zone), or a link without one
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Gateway {
    pub address: Option<String>,
    pub interface: String,
}

// The address of a server through the network, never through the tunnel, which it carries: route -q -n add
// -inet 203.0.113.1 -gateway 192.168.1.1
pub fn host_route_args(action: Action, address: IpAddr, gateway: &Gateway) -> Vec<String> {
    let mut args = strings(&["-q", "-n", action.word(), family(address), &address.to_string()]);
    match &gateway.address {
        Some(router) => args.extend(strings(&["-gateway", router])),
        None => args.extend(strings(&["-interface", &gateway.interface])),
    }
    args
}

// Whether the address of a server is in the routes of the tunnel: it needs its own route through the network
pub fn needs_host_route(routes: &[IpNet], address: IpAddr) -> bool {
    routes.iter().any(|route| route.contains(address))
}

// The default route of the network in netstat -nr -f inet (or inet6): the first one with a router, out of the
// tunnels, the main one before the ones scoped to an interface (flag I)
pub fn parse_default_route(netstat: &str, ipv6: bool) -> Option<Gateway> {
    let mut found: Vec<(bool, Gateway)> = Vec::new();
    for line in netstat.lines() {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 4 || columns[0] != "default" || columns[1].starts_with("link#") {
            continue;
        }
        let interface = columns[3];
        if interface.starts_with("utun") || interface.starts_with("lo") {
            continue;
        }
        // fe80::1%en0: the zone is the interface
        let address = columns[1].split('%').next().unwrap_or("");
        if address.parse::<IpAddr>().map_or(true, |address| address.is_ipv6() != ipv6) {
            continue;
        }
        let gateway = Gateway { address: Some(columns[1].to_string()), interface: interface.to_string() };
        found.push((columns[2].contains('I'), gateway));
    }
    found.sort_by_key(|(scoped, _)| *scoped);
    found.into_iter().next().map(|(_, gateway)| gateway)
}

// "interface: en0" in route -n get
pub fn parse_route_interface(text: &str) -> Option<String> {
    text.lines().find_map(|line| line.trim().strip_prefix("interface:").map(|name| name.trim().to_string()))
}

// The way to an address, as route -n get says it
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Way {
    // through a router, or the point-to-point link of the default route
    Gateway(Gateway),
    // on a network of the computer, its interface: route writes no router then, a link#12 or a hardware address
    Local(String),
}

impl Way {
    fn interface(&self) -> &str {
        match self {
            Way::Gateway(gateway) => &gateway.interface,
            Way::Local(interface) => interface,
        }
    }
}

pub fn parse_route_way(text: &str) -> Option<Way> {
    let value = |key: &str| text.lines().find_map(|line| line.trim().strip_prefix(key).map(|value| value.trim().to_string()));
    let interface = value("interface:")?;
    let router = value("gateway:").filter(|gateway| gateway.split('%').next().is_some_and(|ip| ip.parse::<IpAddr>().is_ok()));
    Some(match router {
        Some(router) => Way::Gateway(Gateway { address: Some(router), interface }),
        None if value("destination:").as_deref() == Some("default") => Way::Gateway(Gateway { address: None, interface }),
        None => Way::Local(interface),
    })
}

// The way to a server out of the tunnel: the one macOS has for its address, so that a server on a network of the
// computer (a virtual machine of this Mac, a firewall of the office) stays on that network and isn't sent to the
// router; the default route of the network when that way goes into a tunnel
pub fn server_way(route: Option<Way>, default: Option<&Gateway>) -> Option<Way> {
    match route {
        Some(way) if !way.interface().starts_with("utun") && !way.interface().starts_with("lo") => Some(way),
        _ => default.cloned().map(Way::Gateway),
    }
}

// "en0: flags=8863<UP,...> mtu 1500" in ifconfig en0
pub fn parse_mtu(ifconfig: &str) -> Option<u32> {
    let first = ifconfig.lines().next()?;
    let mut words = first.split_whitespace();
    words.by_ref().find(|word| *word == "mtu")?;
    words.next()?.parse().ok()
}

// networksetup -listallnetworkservices: a line of explanation, then the services, the ones off with a *
pub fn parse_services(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_string)
        .collect()
}

// networksetup -getdnsservers or -getsearchdomains: one value a line, or a sentence when there's none
pub fn parse_values(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    if lines.iter().any(|line| line.contains(' ')) {
        return Vec::new();
    }
    lines.into_iter().map(str::to_string).collect()
}

// networksetup -setdnsservers Wi-Fi 10.0.0.1, or Empty for the ones of the network again
pub fn set_values_args(option: &str, service: &str, values: &[String]) -> Vec<String> {
    let mut args = vec![option.to_string(), service.to_string()];
    if values.is_empty() {
        args.push("Empty".to_string());
    } else {
        args.extend(values.iter().cloned());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(texts: &[&str]) -> Vec<IpNet> {
        texts.iter().map(|text| IpNet::parse(text).unwrap()).collect()
    }

    #[test]
    fn routes() {
        let routes = tunnel_routes(&nets(&["0.0.0.0/0", "::/0", "10.103.1.2/24", "10.103.1.0/24"]));
        let texts: Vec<String> = routes.iter().map(ToString::to_string).collect();
        assert_eq!(texts, ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "10.103.1.0/24"]);
        assert_eq!(
            route_args(Action::Add, &routes[4], "utun5"),
            ["-q", "-n", "add", "-inet", "10.103.1.0/24", "-interface", "utun5"]
        );
        assert_eq!(route_args(Action::Delete, &routes[2], "utun5")[2..5], ["delete", "-inet6", "::/1"]);
        assert_eq!(
            address_args("utun5", &IpNet::parse("10.103.1.2/24").unwrap()),
            ["utun5", "inet", "10.103.1.2/24", "10.103.1.2", "alias"]
        );
        assert_eq!(address_args("utun5", &IpNet::parse("fd00::2/64").unwrap()), ["utun5", "inet6", "fd00::2/64", "alias"]);
        // the server out of the tunnel: only when the tunnel would carry it
        let full = tunnel_routes(&nets(&["0.0.0.0/0"]));
        assert!(needs_host_route(&full, "203.0.113.1".parse().unwrap()));
        assert!(!needs_host_route(&nets(&["10.103.1.0/24"]), "203.0.113.1".parse().unwrap()));
        let gateway = Gateway { address: Some("192.168.1.1".into()), interface: "en0".into() };
        assert_eq!(
            host_route_args(Action::Add, "203.0.113.1".parse().unwrap(), &gateway),
            ["-q", "-n", "add", "-inet", "203.0.113.1", "-gateway", "192.168.1.1"]
        );
        let link = Gateway { address: None, interface: "en5".into() };
        assert_eq!(host_route_args(Action::Delete, "203.0.113.1".parse().unwrap(), &link)[5..], ["-interface", "en5"]);
    }

    #[test]
    fn the_way_to_a_server() {
        let router = Gateway { address: Some("192.168.1.1".into()), interface: "en0".into() };
        // on the internet: through the router
        let internet = "   route to: 203.0.113.10\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  \
                        interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(parse_route_way(internet), Some(Way::Gateway(router.clone())));
        // a firewall on the network of the computer, its hardware address known (from a Mac): no router
        let known = "   route to: 192.168.100.108\ndestination: 192.168.100.108\n  interface: en0\n      \
                     flags: <UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE,IFREF>\n";
        assert_eq!(parse_route_way(known), Some(Way::Local("en0".into())));
        let mac = "   route to: 192.168.100.108\ndestination: 192.168.100.108\n    gateway: 52:95:b4:11:ad:cf\n  \
                   interface: en0\n";
        assert_eq!(parse_route_way(mac), Some(Way::Local("en0".into())));
        let network = "   route to: 192.168.64.3\ndestination: 192.168.64.0\n       mask: 255.255.255.0\n  \
                       interface: bridge100\n      flags: <UP,DONE,CLONING>\n";
        assert_eq!(parse_route_way(network), Some(Way::Local("bridge100".into())));
        // the default route on a point-to-point link: through its interface
        let ppp = "   route to: 203.0.113.10\ndestination: default\n       mask: default\n  interface: ppp0\n";
        assert_eq!(parse_route_way(ppp), Some(Way::Gateway(Gateway { address: None, interface: "ppp0".into() })));
        assert_eq!(parse_route_way("route: writing to routing socket: not in table\n"), None);
        let v6 = "   route to: 2001:db8::10\ndestination: default\n    gateway: fe80::1%en0\n  interface: en0\n";
        assert_eq!(
            parse_route_way(v6),
            Some(Way::Gateway(Gateway { address: Some("fe80::1%en0".into()), interface: "en0".into() }))
        );

        assert_eq!(server_way(Some(Way::Local("en0".into())), Some(&router)), Some(Way::Local("en0".into())));
        // a way into a tunnel, this one or another VPN: the router of the network
        assert_eq!(server_way(Some(Way::Local("utun4".into())), Some(&router)), Some(Way::Gateway(router.clone())));
        assert_eq!(server_way(None, Some(&router)), Some(Way::Gateway(router.clone())));
        assert_eq!(server_way(None, None), None);
    }

    #[test]
    fn the_network() {
        let netstat = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n\
                       default            link#20            UCSIg              utun3\n\
                       default            192.168.7.1        UGScIg               en7\n\
                       default            192.168.1.1        UGScg                en0\n\
                       127                127.0.0.1          UCS                  lo0\n";
        assert_eq!(
            parse_default_route(netstat, false),
            Some(Gateway { address: Some("192.168.1.1".into()), interface: "en0".into() })
        );
        assert_eq!(parse_default_route(netstat, true), None);
        let netstat6 = "Internet6:\nDestination   Gateway        Flags   Netif Expire\n\
                        default       fe80::%utun0   UGcIg   utun0\n\
                        default       fe80::1%en0    UGcg    en0\n";
        assert_eq!(
            parse_default_route(netstat6, true),
            Some(Gateway { address: Some("fe80::1%en0".into()), interface: "en0".into() })
        );
        assert_eq!(parse_route_interface("   route to: 203.0.113.1\n  gateway: 192.168.1.1\n  interface: en0\n"), Some("en0".into()));
        assert_eq!(parse_mtu("en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 00:00\n"), Some(1500));
        assert_eq!(parse_mtu("nothing"), None);
        let services = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nUSB 10/100 LAN\n";
        assert_eq!(parse_services(services), ["Wi-Fi", "USB 10/100 LAN"]);
        assert_eq!(parse_values("There aren't any DNS Servers set on Wi-Fi.\n"), Vec::<String>::new());
        assert_eq!(parse_values("1.1.1.1\n2606:4700:4700::1111\n"), ["1.1.1.1", "2606:4700:4700::1111"]);
        assert_eq!(set_values_args("-setdnsservers", "Wi-Fi", &[]), ["-setdnsservers", "Wi-Fi", "Empty"]);
        assert_eq!(set_values_args("-setsearchdomains", "Wi-Fi", &["corp.example".into()])[2], "corp.example");
    }
}
