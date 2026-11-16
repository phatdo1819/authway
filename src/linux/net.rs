// The addresses, routes and DNS servers of a tunnel on Linux, as wg-quick sets them, with ip and resolvectl
// (commands.rs makes their arguments). The routes of the tunnel go with its interface; the route that keeps the server
// out of the tunnel and the DNS servers are taken back when the tunnel goes off, and at the start of the service too,
// if it stopped without it. The routes and DNS servers that wait for the login come and go with it. And the
// connections that must go out through the tunnel only.

use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::unix::fs::symlink;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::commands;
use crate::conf::{Config, IpNet};
use crate::log;
use crate::manager::Steps;
use crate::names;
use crate::plan::{self, Action, Gateway, Way};
use crate::setup;

// the MTU of WireGuard on an Ethernet of 1500
pub const DEFAULT_MTU: u32 = 1420;
const MIN_IPV6_MTU: u32 = 1280;
// IPv6, UDP and WireGuard
const OVERHEAD: u32 = 80;
// how often the routes and the DNS servers are looked at again, after a change of network
const UPKEEP: Duration = Duration::from_secs(5);
const RESOLV_CONF: &str = "/etc/resolv.conf";

fn ip() -> Result<PathBuf, String> {
    setup::tool("ip").ok_or_else(|| "ip isn't installed (iproute2)".to_string())
}

// a command of the system, its output
fn run(program: &Path, args: &[String]) -> Result<String, String> {
    let output = Command::new(program).args(args).output().map_err(|error| format!("{}: {}", program.display(), error))?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("{} {}: {}", program.display(), args.join(" "), error));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_ip(args: &[String]) -> Result<String, String> {
    run(&ip()?, args)
}

fn run_logged(program: &Path, args: &[String]) -> bool {
    match run(program, args) {
        Ok(_) => true,
        Err(error) => {
            log!("{}", error);
            false
        }
    }
}

fn ip_logged(args: &[String]) -> bool {
    match ip() {
        Ok(ip) => run_logged(&ip, args),
        Err(error) => {
            log!("{}", error);
            false
        }
    }
}

pub fn interface_index(name: &str) -> Result<u32, String> {
    let name = CString::new(name).map_err(|_| "not a name of interface".to_string())?;
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(format!("can't find the interface: {}", io::Error::last_os_error())),
        index => Ok(index),
    }
}

fn interface_name(index: u32) -> Option<String> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    let found = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    (!found.is_null()).then(|| unsafe { CStr::from_ptr(name.as_ptr()) }.to_string_lossy().to_string())
}

// the loopback, the interface of the tunnels of the tests
pub fn loopback_interface() -> Option<u32> {
    interface_index("lo").ok()
}

// the default routes of the network, out of the tunnels: IPv4, IPv6
fn gateways() -> (Option<Gateway>, Option<Gateway>) {
    let read = |ipv6: bool| {
        run_ip(&commands::default_route_args(ipv6))
            .ok()
            .and_then(|text| commands::parse_default_route(&text, &names::interface_prefix()))
    };
    (read(false), read(true))
}

// the way that the routes choose for the address
fn route_way(address: IpAddr) -> Option<Way> {
    run_ip(&commands::route_get_args(address)).ok().and_then(|text| commands::parse_route_get(&text))
}

// The index of the network interface that the routes choose for the address
pub fn best_interface(address: &SocketAddr) -> Option<u32> {
    interface_index(route_way(address.ip())?.interface()).ok()
}

// The MTU for a tunnel to the endpoint: the one of the interface that reaches it, less the headers of WireGuard
pub fn auto_mtu(endpoint: &SocketAddr) -> u32 {
    let Some(way) = route_way(endpoint.ip()) else { return DEFAULT_MTU };
    let file = Path::new("/sys/class/net").join(way.interface()).join("mtu");
    match fs::read_to_string(file).ok().and_then(|text| commands::parse_mtu(&text)) {
        Some(mtu) => mtu.saturating_sub(OVERHEAD).clamp(MIN_IPV6_MTU, DEFAULT_MTU),
        None => DEFAULT_MTU,
    }
}

// The DNS servers. With systemd-resolved, the ones of the interface of the tunnel, for every name: they go with the
// interface. Without it, /etc/resolv.conf: the tunnels write theirs in it, the last one that goes off puts the file of
// before back, kept in a file until then.
#[derive(Serialize, Deserialize, Clone, Default)]
struct ResolvBackup {
    // the file was a link, to the one of systemd-resolved or NetworkManager
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    text: String,
}

struct DnsState {
    // the tunnels that set DNS servers in /etc/resolv.conf, the last one wins
    owners: Vec<(u64, Vec<String>, Vec<String>)>,
    backup: Option<ResolvBackup>,
}

static DNS: Mutex<DnsState> = Mutex::new(DnsState { owners: Vec::new(), backup: None });

fn backup_file() -> PathBuf {
    setup::support_dir().join("resolv.conf.backup")
}

fn resolvectl() -> Option<PathBuf> {
    setup::tool("resolvectl")
}

// systemd-resolved answers for the computer
fn uses_resolved() -> bool {
    resolvectl().is_some() && fs::read_to_string(RESOLV_CONF).is_ok_and(|text| commands::uses_resolved(&text))
}

fn read_resolv_conf() -> ResolvBackup {
    let link = fs::read_link(RESOLV_CONF).ok().map(|target| target.display().to_string());
    ResolvBackup { link, text: fs::read_to_string(RESOLV_CONF).unwrap_or_default() }
}

// a new file in place of the link or the file there, whole
fn write_resolv_conf(text: &str) {
    let temporary = format!("{}.{}.new", RESOLV_CONF, names::PRODUCT.to_lowercase());
    let written = fs::write(&temporary, text).and_then(|_| fs::rename(&temporary, RESOLV_CONF));
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        log!("can't write {}: {}", RESOLV_CONF, error);
    }
}

fn restore(backup: &ResolvBackup) {
    match &backup.link {
        Some(target) => {
            let _ = fs::remove_file(RESOLV_CONF);
            if let Err(error) = symlink(target, RESOLV_CONF) {
                log!("can't link {} to {} again: {}", RESOLV_CONF, target, error);
            }
        }
        None => write_resolv_conf(&backup.text),
    }
    let _ = fs::remove_file(backup_file());
}

fn keep_backup(backup: &ResolvBackup) {
    if let Ok(data) = serde_json::to_vec_pretty(backup) {
        let _ = fs::write(backup_file(), data);
    }
}

fn take_resolv_conf(owner: u64, servers: Vec<String>, search: Vec<String>) {
    let mut state = DNS.lock().unwrap_or_else(|error| error.into_inner());
    if state.owners.is_empty() {
        let backup = read_resolv_conf();
        keep_backup(&backup);
        state.backup = Some(backup);
    }
    write_resolv_conf(&commands::resolv_conf(&servers, &search));
    state.owners.push((owner, servers, search));
}

fn release_resolv_conf(owner: u64) {
    let mut state = DNS.lock().unwrap_or_else(|error| error.into_inner());
    let before = state.owners.len();
    state.owners.retain(|(id, _, _)| *id != owner);
    if state.owners.len() == before {
        return;
    }
    match state.owners.last() {
        Some((_, servers, search)) => write_resolv_conf(&commands::resolv_conf(servers, search)),
        None => {
            if let Some(backup) = state.backup.take() {
                restore(&backup);
            }
        }
    }
}

// after a change of network: NetworkManager or a DHCP client wrote /etc/resolv.conf again. What they wrote is the
// file of the network now, to put back; the one of the tunnel goes again.
fn renew_resolv_conf() {
    let mut state = DNS.lock().unwrap_or_else(|error| error.into_inner());
    let Some((_, servers, search)) = state.owners.last().cloned() else { return };
    let now = read_resolv_conf();
    if commands::is_ours(&now.text) && now.link.is_none() {
        return;
    }
    log!("{} changed: the DNS servers of the VPN again", RESOLV_CONF);
    keep_backup(&now);
    state.backup = Some(now);
    write_resolv_conf(&commands::resolv_conf(&servers, &search));
}

// At the start of the service: the /etc/resolv.conf of before, if it stopped while a tunnel had its own
pub fn restore_dns_backup() {
    let Ok(data) = fs::read(backup_file()) else { return };
    if let Ok(backup) = serde_json::from_slice::<ResolvBackup>(&data) {
        log!("the DNS servers of before the last tunnels are back");
        restore(&backup);
    }
    let _ = fs::remove_file(backup_file());
}

// The routes of the servers out of the tunnels, with the tunnel of each, kept in a file until they're taken back: a
// service that stopped without it takes them back at its next start. The routes of the tunnels go with their
// interface, these don't.
static HOST_ROUTES: Mutex<Vec<(u64, plan::HostRoute)>> = Mutex::new(Vec::new());

fn host_routes_file() -> PathBuf {
    setup::support_dir().join("host-routes.json")
}

fn keep_host_routes(change: impl FnOnce(&mut Vec<(u64, plan::HostRoute)>)) {
    let mut routes = HOST_ROUTES.lock().unwrap_or_else(|error| error.into_inner());
    change(&mut routes);
    let list: Vec<plan::HostRoute> = routes.iter().map(|(_, route)| route.clone()).collect();
    if list.is_empty() {
        let _ = fs::remove_file(host_routes_file());
    } else if let Err(error) = fs::write(host_routes_file(), plan::host_routes_text(&list)) {
        log!("can't keep the routes of the servers: {}", error);
    }
}

// At the start of the service: the routes of the servers that a service that stopped left behind
pub fn restore_host_routes() {
    let Ok(data) = fs::read(host_routes_file()) else { return };
    for route in plan::parse_host_routes(&data) {
        if run_ip(&commands::host_route_args(Action::Delete, route.address, &route.gateway)).is_ok() {
            log!("the route of before to the server {} is gone", route.address);
        }
    }
    let _ = fs::remove_file(host_routes_file());
}

static NEXT_OWNER: Mutex<u64> = Mutex::new(1);

#[derive(Clone, Copy, PartialEq)]
enum DnsWay {
    Resolved,
    ResolvConf,
}

// What a tunnel changed in the network, taken back when it's dropped
pub struct Network {
    interface: String,
    owner: u64,
    // all the networks of the tunnel, after the login too
    routes: Vec<IpNet>,
    // the ones that wait for the login, see manager::Steps; on while logged_in
    after: Vec<IpNet>,
    logged_in: bool,
    // the DNS servers and search domains of the configuration, set with the routes of after the login when dns_after
    dns: Vec<String>,
    dns_search: Vec<String>,
    dns_after: bool,
    // where the DNS servers are, while they're set
    dns_set: Option<DnsWay>,
    // the servers whose address the tunnel would carry: each has a route through the network
    servers: Vec<IpAddr>,
    host_routes: Vec<(IpAddr, Gateway)>,
    gateways: (Option<Gateway>, Option<Gateway>),
    checked: Instant,
}

impl Network {
    pub fn configure(
        interface: &str,
        config: &Config,
        mtu: u32,
        endpoints: &[Option<SocketAddr>],
        steps: &Steps,
    ) -> Result<Network, String> {
        let owner = {
            let mut next = NEXT_OWNER.lock().unwrap_or_else(|error| error.into_inner());
            *next += 1;
            *next
        };
        let before = plan::tunnel_routes(&steps.before);
        let after = plan::tunnel_routes(&steps.after).into_iter().filter(|net| !before.contains(net)).collect();
        let mut network = Network {
            interface: interface.to_string(),
            owner,
            routes: plan::tunnel_routes(&config.routes()),
            after,
            logged_in: false,
            dns: config.dns.iter().map(ToString::to_string).collect(),
            dns_search: config.dns_search.clone(),
            dns_after: steps.dns_after,
            dns_set: None,
            servers: Vec::new(),
            host_routes: Vec::new(),
            // before the routes of the tunnel
            gateways: gateways(),
            checked: Instant::now(),
        };
        for net in &config.addresses {
            run_ip(&commands::address_args(interface, net)).map_err(|error| format!("can't set the address {}: {}", net, error))?;
        }
        let mtu = if config.addresses.iter().any(|net| net.addr.is_ipv6()) { mtu.max(MIN_IPV6_MTU) } else { mtu };
        run_ip(&commands::link_up_args(interface, mtu)).map_err(|error| format!("can't turn the interface on: {}", error))?;
        for endpoint in endpoints.iter().flatten() {
            network.add_server(endpoint.ip());
        }
        for net in &before {
            ip_logged(&commands::route_args(Action::Add, net, interface));
        }
        if !network.dns_after {
            network.set_dns(true);
        }
        Ok(network)
    }

    fn set_dns(&mut self, on: bool) {
        if on && self.dns_set.is_none() && (!self.dns.is_empty() || !self.dns_search.is_empty()) {
            if uses_resolved() {
                let resolvectl = resolvectl().expect("found");
                let mut done = self.dns.is_empty() || run_logged(&resolvectl, &commands::resolvectl_dns_args(&self.interface, &self.dns));
                done &= run_logged(&resolvectl, &commands::resolvectl_domain_args(&self.interface, &self.dns_search));
                // older versions of systemd don't know it: the routing domain ~. is enough there
                let _ = run(&resolvectl, &commands::resolvectl_default_route_args(&self.interface));
                if !done {
                    log!("{}: the DNS servers of the VPN aren't all set", self.interface);
                }
                self.dns_set = Some(DnsWay::Resolved);
            } else {
                take_resolv_conf(self.owner, self.dns.clone(), self.dns_search.clone());
                self.dns_set = Some(DnsWay::ResolvConf);
            }
        } else if !on {
            match self.dns_set.take() {
                Some(DnsWay::Resolved) => {
                    if let Some(resolvectl) = resolvectl() {
                        run_logged(&resolvectl, &commands::resolvectl_revert_args(&self.interface));
                    }
                }
                Some(DnsWay::ResolvConf) => release_resolv_conf(self.owner),
                None => {}
            }
        }
    }

    // The routes and the DNS servers that wait for the login: on with it, off again when the session ends
    pub fn after_login(&mut self, on: bool) {
        if on == self.logged_in {
            return;
        }
        self.logged_in = on;
        let action = if on { Action::Add } else { Action::Delete };
        for net in &self.after {
            ip_logged(&commands::route_args(action, net, &self.interface));
        }
        if self.dns_after {
            self.set_dns(on);
        }
    }

    // the way of the system to the address, unless it goes into a tunnel: then the default route of the network
    fn way_to(&self, address: IpAddr) -> Option<Way> {
        let default = if address.is_ipv4() { self.gateways.0.as_ref() } else { self.gateways.1.as_ref() };
        commands::server_way(route_way(address), default, &names::interface_prefix())
    }

    // a server, at its first address or at a fallback: out of the tunnel when the tunnel would carry it
    pub fn add_server(&mut self, address: IpAddr) {
        if !plan::needs_host_route(&self.routes, address) || self.servers.contains(&address) {
            return;
        }
        self.servers.push(address);
        self.add_host_route(address);
    }

    fn add_host_route(&mut self, address: IpAddr) {
        let gateway = match self.way_to(address) {
            Some(Way::Gateway(gateway)) => gateway,
            // on a network of the computer: the route of that network, more precise than the ones of the tunnel,
            // keeps it out
            Some(Way::Local(interface)) => {
                log!("{}: {} is on the network of {}", self.interface, address, interface);
                return;
            }
            None => {
                log!("{}: no route out of the tunnel to {}", self.interface, address);
                return;
            }
        };
        if ip_logged(&commands::host_route_args(Action::Add, address, &gateway)) {
            let route = plan::HostRoute { address, gateway: gateway.clone() };
            keep_host_routes(|routes| routes.push((self.owner, route)));
            self.host_routes.push((address, gateway));
        }
    }

    fn remove_host_routes(&mut self) {
        for (address, gateway) in std::mem::take(&mut self.host_routes) {
            let _ = run_ip(&commands::host_route_args(Action::Delete, address, &gateway));
        }
        let owner = self.owner;
        keep_host_routes(|routes| routes.retain(|(other, _)| *other != owner));
    }

    // every UPKEEP: another network, another router; /etc/resolv.conf written again by the network
    pub fn upkeep(&mut self) {
        if self.checked.elapsed() < UPKEEP {
            return;
        }
        self.checked = Instant::now();
        if self.dns_set == Some(DnsWay::ResolvConf) {
            renew_resolv_conf();
        }
        let now = gateways();
        if now == self.gateways {
            return;
        }
        log!("{}: the network changed", self.interface);
        self.remove_host_routes();
        self.gateways = now;
        for address in self.servers.clone() {
            self.add_host_route(address);
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.remove_host_routes();
        self.set_dns(false);
    }
}

// whether the address is one of the interface
pub fn has_address(interface: u32, address: IpAddr) -> bool {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return false;
    }
    let mut found = false;
    let mut item = list;
    while !item.is_null() && !found {
        let entry = unsafe { &*item };
        item = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        if unsafe { libc::if_nametoindex(entry.ifa_name) } != interface {
            continue;
        }
        let family = i32::from(unsafe { (*entry.ifa_addr).sa_family });
        found = match family {
            libc::AF_INET => {
                let socket = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(socket.sin_addr.s_addr))) == address
            }
            libc::AF_INET6 => {
                let socket = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                IpAddr::V6(Ipv6Addr::from(socket.sin6_addr.s6_addr)) == address
            }
            _ => false,
        };
    }
    unsafe { libc::freeifaddrs(list) };
    found
}

// A socket, closed when dropped unless it became a TcpStream
struct Socket(i32);

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn check(result: i32) -> io::Result<()> {
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_nonblocking(socket: i32, on: bool) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(socket, libc::F_GETFL) };
    check(flags)?;
    let flags = if on { flags | libc::O_NONBLOCK } else { flags & !libc::O_NONBLOCK };
    check(unsafe { libc::fcntl(socket, libc::F_SETFL, flags) })
}

// A TCP connection that goes out through the interface of the tunnel only, whatever the routes say: a more specific
// route of the local network, from its DHCP server for example (option 121, "TunnelVision"), can't take it
// elsewhere. Refused when it comes from an address that isn't one of the interface, before anything is sent.
// SO_BINDTODEVICE needs no privilege since Linux 5.7.
pub fn connect_through(address: SocketAddrV4, interface: u32, timeout: Duration) -> io::Result<TcpStream> {
    if interface == 0 {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "the interface of the VPN isn't known yet"));
    }
    let name = interface_name(interface).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the interface of the VPN is gone"))?;
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, libc::IPPROTO_TCP) };
    check(raw)?;
    let socket = Socket(raw);
    // the interface, before connect
    check(unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const libc::c_void,
            name.len() as libc::socklen_t,
        )
    })?;
    set_nonblocking(raw, true)?;
    let mut target: libc::sockaddr_in = unsafe { zeroed() };
    target.sin_family = libc::AF_INET as libc::sa_family_t;
    target.sin_port = address.port().to_be();
    target.sin_addr.s_addr = u32::from(*address.ip()).to_be();
    let result = unsafe {
        libc::connect(raw, &target as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_in>() as libc::socklen_t)
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let mut poll = libc::pollfd { fd: raw, events: libc::POLLOUT, revents: 0 };
        let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
        match unsafe { libc::poll(&mut poll, 1, milliseconds) } {
            -1 => return Err(io::Error::last_os_error()),
            0 => return Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out")),
            _ => {}
        }
        let mut error: libc::c_int = 0;
        let mut size = size_of::<libc::c_int>() as libc::socklen_t;
        check(unsafe {
            libc::getsockopt(raw, libc::SOL_SOCKET, libc::SO_ERROR, &mut error as *mut _ as *mut libc::c_void, &mut size)
        })?;
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
    }
    set_nonblocking(raw, false)?;
    std::mem::forget(socket);
    let stream = unsafe { TcpStream::from_raw_fd(raw) };
    let local = stream.local_addr()?;
    if !has_address(interface, local.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the connection goes out from {}, not through the VPN", local.ip()),
        ));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn loopback() -> u32 {
        loopback_interface().expect("lo")
    }

    #[test]
    fn through_the_interface() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let SocketAddr::V4(address) = listener.local_addr().unwrap() else { unreachable!() };
        let mut stream = connect_through(address, loopback(), Duration::from_secs(3)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream.write_all(b"ping").unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        let mut data = [0u8; 4];
        accepted.read_exact(&mut data).unwrap();
        accepted.write_all(b"pong").unwrap();
        stream.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"pong");
        assert!(has_address(loopback(), IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!has_address(loopback(), "192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn nowhere_else() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let SocketAddr::V4(address) = listener.local_addr().unwrap() else { unreachable!() };
        assert_eq!(connect_through(address, 0, Duration::from_secs(3)).unwrap_err().kind(), io::ErrorKind::NotConnected);
        // a closed port: refused, not a timeout
        drop(listener);
        let started = Instant::now();
        assert!(connect_through(address, loopback(), Duration::from_secs(10)).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
