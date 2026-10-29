// The addresses, routes and DNS servers of a tunnel on macOS, as wg-quick sets them there, with the commands of
// macOS (plan.rs makes their arguments). The routes of the tunnel go with its interface; the route that keeps the
// server out of the tunnel and the DNS servers are taken back when the tunnel goes off, and the DNS servers at the
// start of the service too, if it stopped without it. The routes and DNS servers that wait for the login come and go
// with it. And the connections that must go out through the tunnel only.

use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::conf::{Config, IpNet};
use crate::log;
use crate::manager::Steps;
use crate::plan::{self, Action, Gateway};
use crate::setup;

// the MTU of WireGuard on an Ethernet of 1500
pub const DEFAULT_MTU: u32 = 1420;
const MIN_IPV6_MTU: u32 = 1280;
// IPv6, UDP and WireGuard
const OVERHEAD: u32 = 80;
// how often the routes and the DNS servers are looked at again, after a change of network
const UPKEEP: Duration = Duration::from_secs(5);

const IFCONFIG: &str = "/sbin/ifconfig";
const ROUTE: &str = "/sbin/route";
const NETSTAT: &str = "/usr/sbin/netstat";
const NETWORKSETUP: &str = "/usr/sbin/networksetup";

// a command of macOS, its output
fn run(program: &str, args: &[String]) -> Result<String, String> {
    let output = Command::new(program).args(args).output().map_err(|error| format!("{}: {}", program, error))?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("{} {}: {}", program, args.join(" "), error));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_logged(program: &str, args: &[String]) -> bool {
    match run(program, args) {
        Ok(_) => true,
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

// the loopback, the interface of the tunnels of the tests
pub fn loopback_interface() -> Option<u32> {
    interface_index("lo0").ok()
}

// the default routes of the network, out of the tunnels: IPv4, IPv6
fn gateways() -> (Option<Gateway>, Option<Gateway>) {
    let read = |family: &str, ipv6: bool| {
        run(NETSTAT, &["-nr".to_string(), "-f".to_string(), family.to_string()])
            .ok()
            .and_then(|text| plan::parse_default_route(&text, ipv6))
    };
    (read("inet", false), read("inet6", true))
}

// the name of the network interface that the routes choose for the address
fn route_interface(address: &SocketAddr) -> Option<String> {
    let family = if address.is_ipv4() { "-inet" } else { "-inet6" };
    let args = ["-n", "get", family, &address.ip().to_string()].map(str::to_string);
    run(ROUTE, &args).ok().and_then(|text| plan::parse_route_interface(&text))
}

// The index of the network interface that the routes choose for the address
pub fn best_interface(address: &SocketAddr) -> Option<u32> {
    interface_index(&route_interface(address)?).ok()
}

// The MTU for a tunnel to the endpoint: the one of the interface that reaches it, less the headers of WireGuard
pub fn auto_mtu(endpoint: &SocketAddr) -> u32 {
    let Some(interface) = route_interface(endpoint) else {
        return DEFAULT_MTU;
    };
    match run(IFCONFIG, &[interface]).ok().and_then(|text| plan::parse_mtu(&text)) {
        Some(mtu) if mtu > 0 => mtu.saturating_sub(OVERHEAD).clamp(MIN_IPV6_MTU, DEFAULT_MTU),
        _ => DEFAULT_MTU,
    }
}

// The DNS servers of the network services, as they were before the tunnels: the tunnels set theirs on every
// service, as wg-quick does, and the last one that goes off puts these back. Kept in a file until then.
#[derive(Serialize, Deserialize, Clone, Default)]
struct ServiceDns {
    service: String,
    servers: Vec<String>,
    search: Vec<String>,
}

struct DnsState {
    // the tunnels that set DNS servers, the last one wins
    owners: Vec<(u64, Vec<String>, Vec<String>)>,
    backup: Vec<ServiceDns>,
}

static DNS: Mutex<DnsState> = Mutex::new(DnsState { owners: Vec::new(), backup: Vec::new() });

fn backup_file() -> PathBuf {
    setup::support_dir().join("dns-backup.json")
}

fn services() -> Vec<String> {
    run(NETWORKSETUP, &["-listallnetworkservices".to_string()]).map(|text| plan::parse_services(&text)).unwrap_or_default()
}

fn read_values(option: &str, service: &str) -> Vec<String> {
    run(NETWORKSETUP, &[option.to_string(), service.to_string()]).map(|text| plan::parse_values(&text)).unwrap_or_default()
}

fn apply_dns(servers: &[String], search: &[String]) {
    for service in services() {
        run_logged(NETWORKSETUP, &plan::set_values_args("-setdnsservers", &service, servers));
        run_logged(NETWORKSETUP, &plan::set_values_args("-setsearchdomains", &service, search));
    }
}

fn restore(backup: &[ServiceDns]) {
    for service in backup {
        run_logged(NETWORKSETUP, &plan::set_values_args("-setdnsservers", &service.service, &service.servers));
        run_logged(NETWORKSETUP, &plan::set_values_args("-setsearchdomains", &service.service, &service.search));
    }
    let _ = fs::remove_file(backup_file());
}

fn take_dns(owner: u64, servers: Vec<String>, search: Vec<String>) {
    let mut state = DNS.lock().unwrap_or_else(|error| error.into_inner());
    if state.owners.is_empty() {
        state.backup = services()
            .into_iter()
            .map(|service| ServiceDns {
                servers: read_values("-getdnsservers", &service),
                search: read_values("-getsearchdomains", &service),
                service,
            })
            .collect();
        if let Ok(data) = serde_json::to_vec_pretty(&state.backup) {
            let _ = fs::write(backup_file(), data);
        }
    }
    apply_dns(&servers, &search);
    state.owners.push((owner, servers, search));
}

fn release_dns(owner: u64) {
    let mut state = DNS.lock().unwrap_or_else(|error| error.into_inner());
    let before = state.owners.len();
    state.owners.retain(|(id, _, _)| *id != owner);
    if state.owners.len() == before {
        return;
    }
    match state.owners.last() {
        Some((_, servers, search)) => apply_dns(servers, search),
        None => {
            let backup = std::mem::take(&mut state.backup);
            restore(&backup);
        }
    }
}

// after a change of network: a service that came, or settings that the system changed back
fn renew_dns() {
    let state = DNS.lock().unwrap_or_else(|error| error.into_inner());
    if let Some((_, servers, search)) = state.owners.last() {
        apply_dns(servers, search);
    }
}

// At the start of the service: the DNS servers of before, if it stopped while a tunnel had its own
pub fn restore_dns_backup() {
    let Ok(data) = fs::read(backup_file()) else { return };
    if let Ok(backup) = serde_json::from_slice::<Vec<ServiceDns>>(&data) {
        log!("the DNS servers of before the last tunnels are back");
        restore(&backup);
    }
    let _ = fs::remove_file(backup_file());
}

static NEXT_OWNER: Mutex<u64> = Mutex::new(1);

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
    // the servers whose address the tunnel would carry: each has a route through the network
    servers: Vec<IpAddr>,
    host_routes: Vec<(IpAddr, Gateway)>,
    gateways: (Option<Gateway>, Option<Gateway>),
    has_dns: bool,
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
            servers: Vec::new(),
            host_routes: Vec::new(),
            // before the routes of the tunnel
            gateways: gateways(),
            has_dns: false,
            checked: Instant::now(),
        };
        for net in &config.addresses {
            run(IFCONFIG, &plan::address_args(interface, net)).map_err(|error| format!("can't set the address {}: {}", net, error))?;
        }
        let mtu = if config.addresses.iter().any(|net| net.addr.is_ipv6()) { mtu.max(MIN_IPV6_MTU) } else { mtu };
        run(IFCONFIG, &[interface.to_string(), "mtu".to_string(), mtu.to_string(), "up".to_string()])
            .map_err(|error| format!("can't turn the interface on: {}", error))?;
        for endpoint in endpoints.iter().flatten() {
            network.add_server(endpoint.ip());
        }
        for net in &before {
            // a network that the computer has already, the local one: the tunnel gets the rest
            run_logged(ROUTE, &plan::route_args(Action::Add, net, interface));
        }
        if !network.dns_after {
            network.set_dns(true);
        }
        Ok(network)
    }

    fn set_dns(&mut self, on: bool) {
        if on && !self.has_dns && (!self.dns.is_empty() || !self.dns_search.is_empty()) {
            take_dns(self.owner, self.dns.clone(), self.dns_search.clone());
            self.has_dns = true;
        } else if !on && self.has_dns {
            release_dns(self.owner);
            self.has_dns = false;
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
            run_logged(ROUTE, &plan::route_args(action, net, &self.interface));
        }
        if self.dns_after {
            self.set_dns(on);
        }
    }

    fn gateway_for(&self, address: IpAddr) -> Option<&Gateway> {
        if address.is_ipv4() {
            self.gateways.0.as_ref()
        } else {
            self.gateways.1.as_ref()
        }
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
        let Some(gateway) = self.gateway_for(address).cloned() else {
            log!("{}: no route out of the tunnel to {}", self.interface, address);
            return;
        };
        // one of before, from a tunnel that went off without taking it back
        let _ = run(ROUTE, &plan::host_route_args(Action::Delete, address, &gateway));
        if run_logged(ROUTE, &plan::host_route_args(Action::Add, address, &gateway)) {
            self.host_routes.push((address, gateway));
        }
    }

    fn remove_host_routes(&mut self) {
        for (address, gateway) in std::mem::take(&mut self.host_routes) {
            let _ = run(ROUTE, &plan::host_route_args(Action::Delete, address, &gateway));
        }
    }

    // every UPKEEP: another network, another router; the DNS servers again on the services
    pub fn upkeep(&mut self) {
        if self.checked.elapsed() < UPKEEP {
            return;
        }
        self.checked = Instant::now();
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
        if self.has_dns {
            renew_dns();
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.remove_host_routes();
        if self.has_dns {
            release_dns(self.owner);
        }
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
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if unsafe { libc::if_nametoindex(name.as_ptr()) } != interface {
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
pub fn connect_through(address: SocketAddrV4, interface: u32, timeout: Duration) -> io::Result<TcpStream> {
    if interface == 0 {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "the interface of the VPN isn't known yet"));
    }
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
    check(raw)?;
    let socket = Socket(raw);
    check(unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    let one: libc::c_int = 1;
    // a write to a closed connection is an error, not the end of the app
    check(unsafe {
        libc::setsockopt(raw, libc::SOL_SOCKET, libc::SO_NOSIGPIPE, &one as *const _ as *const libc::c_void, 4)
    })?;
    // the index of the interface, before connect
    check(unsafe {
        libc::setsockopt(raw, libc::IPPROTO_IP, libc::IP_BOUND_IF, &interface as *const u32 as *const libc::c_void, 4)
    })?;
    set_nonblocking(raw, true)?;
    let mut target: libc::sockaddr_in = unsafe { zeroed() };
    target.sin_len = size_of::<libc::sockaddr_in>() as u8;
    target.sin_family = libc::AF_INET as libc::sa_family_t;
    target.sin_port = address.port().to_be();
    target.sin_addr.s_addr = u32::from(*address.ip()).to_be();
    let result = unsafe {
        libc::connect(raw, &target as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_in>() as u32)
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
        loopback_interface().expect("lo0")
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
