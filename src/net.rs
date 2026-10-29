// The addresses, routes and DNS servers of a tunnel adapter, as the example of WireGuardNT sets them. They go away
// with the adapter; the routes and DNS servers that wait for the login come and go with it. And the connections that
// must go out through it only.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::windows::io::FromRawSocket;
use std::ptr;
use std::sync::Once;
use std::time::Duration;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteIpForwardEntry2, GetBestInterfaceEx, GetIpInterfaceEntry, GetUnicastIpAddressEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, SetInterfaceDnsSettings, SetIpInterfaceEntry,
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    DNS_SETTING_SEARCHLIST, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    closesocket, connect, getsockopt, ioctlsocket, select, setsockopt, IpDadStatePreferred, RouterDiscoveryDisabled,
    WSAGetLastError, WSASocketW, WSAStartup, ADDRESS_FAMILY, AF_INET, AF_INET6, FD_SET, FIONBIO, INVALID_SOCKET,
    IPPROTO_IP, IPPROTO_TCP, IP_UNICAST_IF, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, SOCK_STREAM, SOL_SOCKET,
    SO_ERROR, TIMEVAL, WSADATA, WSAEWOULDBLOCK, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
};

use crate::conf::{Config, IpNet};
use crate::wg::{ip_sockaddr, to_sockaddr};
use crate::win::error_message;

// the MTU of WireGuard on an Ethernet of 1500
pub const DEFAULT_MTU: u32 = 1420;
const MIN_IPV6_MTU: u32 = 1280;
// IPv6, UDP and WireGuard
const OVERHEAD: u32 = 80;

// the routes of before the login, and the DNS servers unless they wait for it (see manager::Steps)
pub fn configure(luid: u64, config: &Config, routes: &[IpNet], dns: bool, mtu: u32) -> Result<(), String> {
    let luid = NET_LUID_LH { Value: luid };
    for net in routes {
        add_route(&luid, net)?;
    }
    for net in &config.addresses {
        add_address(&luid, net)?;
    }
    set_interface(&luid, AF_INET, mtu)?;
    set_interface(&luid, AF_INET6, mtu)?;
    if !dns {
        return Ok(());
    }
    set_dns(&luid, &config.dns, &config.dns_search)
}

// The routes and the DNS servers that wait for the login: on with it, off again when the session ends, all of them
// even when one fails
pub fn after_login(luid: u64, routes: &[IpNet], dns: &[IpAddr], search: &[String], on: bool) -> Result<(), String> {
    let luid = NET_LUID_LH { Value: luid };
    if on {
        for net in routes {
            add_route(&luid, net)?;
        }
        return set_dns(&luid, dns, search);
    }
    let mut result = Ok(());
    for net in routes {
        result = result.and(delete_route(&luid, net));
    }
    result.and(clear_dns(&luid, dns, search))
}

fn route_row(luid: &NET_LUID_LH, network: &IpNet) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = *luid;
    row.DestinationPrefix.Prefix = ip_sockaddr(network.addr);
    row.DestinationPrefix.PrefixLength = network.prefix;
    // on the link of the tunnel: no gateway
    let any: IpAddr = if network.addr.is_ipv4() { [0u8; 4].into() } else { [0u8; 16].into() };
    row.NextHop = ip_sockaddr(any);
    row.Metric = 0;
    row
}

fn add_route(luid: &NET_LUID_LH, net: &IpNet) -> Result<(), String> {
    let network = net.network();
    let result = unsafe { CreateIpForwardEntry2(&route_row(luid, &network)) };
    if result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS {
        return Err(format!("can't add the route to {}: {}", network, error_message(result)));
    }
    Ok(())
}

fn delete_route(luid: &NET_LUID_LH, net: &IpNet) -> Result<(), String> {
    let network = net.network();
    let result = unsafe { DeleteIpForwardEntry2(&route_row(luid, &network)) };
    if result != NO_ERROR && result != ERROR_NOT_FOUND {
        return Err(format!("can't remove the route to {}: {}", network, error_message(result)));
    }
    Ok(())
}

fn add_address(luid: &NET_LUID_LH, net: &IpNet) -> Result<(), String> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = *luid;
    row.Address = ip_sockaddr(net.addr);
    row.OnLinkPrefixLength = net.prefix;
    row.DadState = IpDadStatePreferred;
    let result = unsafe { CreateUnicastIpAddressEntry(&row) };
    if result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS {
        return Err(format!("can't set the address {}: {}", net, error_message(result)));
    }
    Ok(())
}

// metric 0, for the routes of the tunnel to win over the others, and the MTU of the tunnel
fn set_interface(luid: &NET_LUID_LH, family: ADDRESS_FAMILY, mtu: u32) -> Result<(), String> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.InterfaceLuid = *luid;
    row.Family = family;
    let result = unsafe { GetIpInterfaceEntry(&mut row) };
    if result == ERROR_NOT_FOUND && family == AF_INET6 {
        // IPv6 is off on this computer
        return Ok(());
    }
    if result != NO_ERROR {
        return Err(format!("can't read the network adapter: {}", error_message(result)));
    }
    row.UseAutomaticMetric = false;
    row.Metric = 0;
    if family == AF_INET {
        row.NlMtu = mtu;
        // GetIpInterfaceEntry gives a value that SetIpInterfaceEntry refuses
        row.SitePrefixLength = 0;
    } else {
        if mtu >= MIN_IPV6_MTU {
            row.NlMtu = mtu;
        }
        row.DadTransmits = 0;
        row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    }
    let result = unsafe { SetIpInterfaceEntry(&mut row) };
    if result != NO_ERROR {
        return Err(format!("can't set the metric and the MTU: {}", error_message(result)));
    }
    Ok(())
}

// For each version of IP: whether it's IPv6, the servers and the search domains, which go with the servers of IPv4,
// or of IPv6 when there are none
fn dns_settings(dns: &[IpAddr], search: &[String]) -> Vec<(bool, String, String)> {
    if dns.is_empty() && search.is_empty() {
        return Vec::new();
    }
    let join = |ipv4: bool| -> String {
        let servers: Vec<String> = dns.iter().filter(|addr| addr.is_ipv4() == ipv4).map(|addr| addr.to_string()).collect();
        servers.join(",")
    };
    let search = search.join(",");
    let ipv4 = join(true);
    let ipv6 = join(false);
    let search_with_ipv6 = ipv4.is_empty() && !ipv6.is_empty();
    let mut settings = Vec::new();
    if !ipv4.is_empty() || !search_with_ipv6 {
        settings.push((false, ipv4, if search_with_ipv6 { String::new() } else { search.clone() }));
    }
    if !ipv6.is_empty() {
        settings.push((true, ipv6, if search_with_ipv6 { search } else { String::new() }));
    }
    settings
}

fn adapter_guid(luid: &NET_LUID_LH) -> Result<GUID, String> {
    let mut guid: GUID = unsafe { zeroed() };
    let result = unsafe { ConvertInterfaceLuidToGuid(luid, &mut guid) };
    if result != NO_ERROR {
        return Err(format!("can't find the network adapter: {}", error_message(result)));
    }
    Ok(guid)
}

fn set_dns(luid: &NET_LUID_LH, dns: &[IpAddr], search: &[String]) -> Result<(), String> {
    let settings = dns_settings(dns, search);
    if settings.is_empty() {
        return Ok(());
    }
    let guid = adapter_guid(luid)?;
    for (ipv6, servers, search) in &settings {
        apply_dns(&guid, *ipv6, servers, (!search.is_empty()).then_some(search.as_str()))?;
    }
    Ok(())
}

// the ones that set_dns set, empty again
fn clear_dns(luid: &NET_LUID_LH, dns: &[IpAddr], search: &[String]) -> Result<(), String> {
    let settings = dns_settings(dns, search);
    if settings.is_empty() {
        return Ok(());
    }
    let guid = adapter_guid(luid)?;
    for (ipv6, _, search) in &settings {
        apply_dns(&guid, *ipv6, "", (!search.is_empty()).then_some(""))?;
    }
    Ok(())
}

// the search domains only when given, an empty list for none
fn apply_dns(guid: &GUID, ipv6: bool, servers: &str, search: Option<&str>) -> Result<(), String> {
    let mut servers = crate::win::wide(servers);
    let mut search_list = crate::win::wide(search.unwrap_or(""));
    let mut settings: DNS_INTERFACE_SETTINGS = unsafe { zeroed() };
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = DNS_SETTING_NAMESERVER as u64;
    settings.NameServer = servers.as_mut_ptr();
    if search.is_some() {
        settings.Flags |= DNS_SETTING_SEARCHLIST as u64;
        settings.SearchList = search_list.as_mut_ptr();
    } else {
        settings.SearchList = ptr::null_mut();
    }
    if ipv6 {
        settings.Flags |= DNS_SETTING_IPV6 as u64;
    }
    let result = unsafe { SetInterfaceDnsSettings(*guid, &settings) };
    if result != NO_ERROR {
        return Err(format!("can't set the DNS servers: {}", error_message(result)));
    }
    Ok(())
}

// The MTU for a tunnel to the endpoint: the one of the network adapter that reaches it, less the headers of
// WireGuard
pub fn auto_mtu(endpoint: &SocketAddr) -> u32 {
    let Some(index) = best_interface(endpoint) else {
        return DEFAULT_MTU;
    };
    let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.InterfaceIndex = index;
    row.Family = if endpoint.is_ipv4() { AF_INET } else { AF_INET6 };
    if unsafe { GetIpInterfaceEntry(&mut row) } != NO_ERROR || row.NlMtu == 0 {
        return DEFAULT_MTU;
    }
    row.NlMtu.saturating_sub(OVERHEAD).clamp(MIN_IPV6_MTU, DEFAULT_MTU)
}

// The index of the network adapter that the routes choose for the address
pub fn best_interface(address: &SocketAddr) -> Option<u32> {
    let address = to_sockaddr(address);
    let mut index = 0u32;
    let result = unsafe { GetBestInterfaceEx(&address as *const _ as *const SOCKADDR, &mut index) };
    (result == NO_ERROR).then_some(index)
}

// the loopback, the network interface of the tunnels of the tests
pub fn loopback_interface() -> Option<u32> {
    best_interface(&SocketAddr::from(([127, 0, 0, 1], 0)))
}

// The index of a network adapter, for the connections that must go out through it
pub fn interface_index(luid: u64) -> Result<u32, String> {
    let luid = NET_LUID_LH { Value: luid };
    let mut index = 0u32;
    let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if result != NO_ERROR {
        return Err(format!("can't find the network adapter: {}", error_message(result)));
    }
    Ok(index)
}

// whether the address is one of the network adapter
pub fn has_address(interface: u32, address: IpAddr) -> bool {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceIndex = interface;
    row.Address = ip_sockaddr(address);
    unsafe { GetUnicastIpAddressEntry(&mut row) == NO_ERROR }
}

// A TCP connection that goes out through the network adapter only, whatever the routes say: a more specific route of
// the local network, from its DHCP server for example (option 121, "TunnelVision"), can't take it elsewhere. Refused
// when it comes from an address that isn't one of the adapter, before anything is sent.
pub fn connect_through(address: SocketAddrV4, interface: u32, timeout: Duration) -> io::Result<TcpStream> {
    if interface == 0 {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "the network adapter of the VPN isn't known yet"));
    }
    let socket = Socket::new()?;
    // in the order of the network, for IPv4; before connect for TCP
    let index = interface.to_be();
    check(unsafe { setsockopt(socket.0, IPPROTO_IP, IP_UNICAST_IF, &index as *const u32 as *const u8, 4) })?;
    socket.connect(address, timeout)?;
    let stream = socket.into_stream();
    let local = stream.local_addr()?;
    if !has_address(interface, local.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the connection goes out from {}, not through the VPN", local.ip()),
        ));
    }
    Ok(stream)
}

// A socket of WinSock, closed when dropped unless it became a TcpStream
struct Socket(SOCKET);

impl Socket {
    fn new() -> io::Result<Socket> {
        // as the standard library before its first socket; WinSock counts the starts and stays up
        static STARTED: Once = Once::new();
        STARTED.call_once(|| unsafe {
            let mut data: WSADATA = zeroed();
            WSAStartup(0x202, &mut data);
        });
        let flags = WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT;
        let socket = unsafe { WSASocketW(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP, ptr::null(), 0, flags) };
        if socket == INVALID_SOCKET {
            return Err(wsa_error());
        }
        Ok(Socket(socket))
    }

    // with a timeout, as TcpStream::connect_timeout
    fn connect(&self, address: SocketAddrV4, timeout: Duration) -> io::Result<()> {
        let mut nonblocking = 1u32;
        check(unsafe { ioctlsocket(self.0, FIONBIO, &mut nonblocking) })?;
        let target = to_sockaddr(&SocketAddr::V4(address));
        let length = size_of::<SOCKADDR_IN>() as i32;
        let result = unsafe { connect(self.0, &target as *const _ as *const SOCKADDR, length) };
        if result == SOCKET_ERROR {
            let code = unsafe { WSAGetLastError() };
            if code != WSAEWOULDBLOCK {
                return Err(io::Error::from_raw_os_error(code));
            }
            let mut writable: FD_SET = unsafe { zeroed() };
            writable.fd_count = 1;
            writable.fd_array[0] = self.0;
            let mut failed = writable;
            let time = TIMEVAL {
                tv_sec: timeout.as_secs().min(i32::MAX as u64) as i32,
                tv_usec: timeout.subsec_micros() as i32,
            };
            match unsafe { select(1, ptr::null_mut(), &mut writable, &mut failed, &time) } {
                SOCKET_ERROR => return Err(wsa_error()),
                0 => return Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out")),
                _ => {}
            }
            let mut error = 0i32;
            let mut size = size_of::<i32>() as i32;
            check(unsafe { getsockopt(self.0, SOL_SOCKET, SO_ERROR, &mut error as *mut i32 as *mut u8, &mut size) })?;
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
        }
        nonblocking = 0;
        check(unsafe { ioctlsocket(self.0, FIONBIO, &mut nonblocking) })
    }

    fn into_stream(self) -> TcpStream {
        let socket = self.0;
        std::mem::forget(self);
        unsafe { TcpStream::from_raw_socket(socket as u64) }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { closesocket(self.0) };
    }
}

fn check(result: i32) -> io::Result<()> {
    if result == SOCKET_ERROR {
        return Err(wsa_error());
    }
    Ok(())
}

fn wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};

    fn loopback() -> u32 {
        best_interface(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("the loopback adapter")
    }

    #[test]
    fn through_the_adapter() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let SocketAddr::V4(address) = listener.local_addr().unwrap() else { unreachable!() };
        let mut stream = connect_through(address, loopback(), Duration::from_secs(3)).unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        // a plain blocking socket again, with its timeouts
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
    fn dns_of_each_version() {
        let addrs = |texts: &[&str]| texts.iter().map(|text| text.parse().unwrap()).collect::<Vec<IpAddr>>();
        let search = vec!["corp.example".to_string()];
        assert!(dns_settings(&[], &[]).is_empty());
        assert_eq!(
            dns_settings(&addrs(&["10.103.1.1", "fd00::1", "10.103.1.2"]), &search),
            [(false, "10.103.1.1,10.103.1.2".into(), "corp.example".into()), (true, "fd00::1".into(), String::new())]
        );
        assert_eq!(dns_settings(&addrs(&["fd00::1"]), &search), [(true, "fd00::1".into(), "corp.example".into())]);
        assert_eq!(dns_settings(&[], &search), [(false, String::new(), "corp.example".into())]);
    }

    #[test]
    fn nowhere_else() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let SocketAddr::V4(address) = listener.local_addr().unwrap() else { unreachable!() };
        let error = connect_through(address, 0, Duration::from_secs(3)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        // the adapter of the internet, when there's one: the loopback is never one of its addresses
        let internet = best_interface(&SocketAddr::from(([192, 0, 2, 1], 0))).filter(|&index| index != loopback());
        if let Some(internet) = internet {
            assert!(connect_through(address, internet, Duration::from_secs(3)).is_err());
        }
        // a closed port: refused, not a timeout
        drop(listener);
        let started = std::time::Instant::now();
        assert!(connect_through(address, loopback(), Duration::from_secs(10)).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
