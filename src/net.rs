// The addresses, routes and DNS servers of a tunnel adapter, as the example of WireGuardNT sets them. They go away
// with the adapter.

use std::mem::zeroed;
use std::net::{IpAddr, SocketAddr};
use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry, GetBestInterfaceEx,
    GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    SetInterfaceDnsSettings, SetIpInterfaceEntry, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
    DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, DNS_SETTING_SEARCHLIST, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, RouterDiscoveryDisabled, ADDRESS_FAMILY, AF_INET, AF_INET6, SOCKADDR,
};

use crate::conf::{Config, IpNet};
use crate::wg::{ip_sockaddr, to_sockaddr};
use crate::win::error_message;

// the MTU of WireGuard on an Ethernet of 1500
pub const DEFAULT_MTU: u32 = 1420;
const MIN_IPV6_MTU: u32 = 1280;
// IPv6, UDP and WireGuard
const OVERHEAD: u32 = 80;

pub fn configure(luid: u64, config: &Config, mtu: u32) -> Result<(), String> {
    let luid = NET_LUID_LH { Value: luid };
    for net in config.routes() {
        add_route(&luid, &net)?;
    }
    for net in &config.addresses {
        add_address(&luid, net)?;
    }
    set_interface(&luid, AF_INET, mtu)?;
    set_interface(&luid, AF_INET6, mtu)?;
    set_dns(&luid, config)
}

fn add_route(luid: &NET_LUID_LH, net: &IpNet) -> Result<(), String> {
    let network = net.network();
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = *luid;
    row.DestinationPrefix.Prefix = ip_sockaddr(network.addr);
    row.DestinationPrefix.PrefixLength = network.prefix;
    // on the link of the tunnel: no gateway
    let any: IpAddr = if network.addr.is_ipv4() { [0u8; 4].into() } else { [0u8; 16].into() };
    row.NextHop = ip_sockaddr(any);
    row.Metric = 0;
    let result = unsafe { CreateIpForwardEntry2(&row) };
    if result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS {
        return Err(format!("can't add the route to {}: {}", network, error_message(result)));
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

fn set_dns(luid: &NET_LUID_LH, config: &Config) -> Result<(), String> {
    if config.dns.is_empty() && config.dns_search.is_empty() {
        return Ok(());
    }
    let mut guid: GUID = unsafe { zeroed() };
    let result = unsafe { ConvertInterfaceLuidToGuid(luid, &mut guid) };
    if result != NO_ERROR {
        return Err(format!("can't find the network adapter: {}", error_message(result)));
    }
    let join = |ipv4: bool| -> String {
        let servers: Vec<String> = config.dns.iter().filter(|addr| addr.is_ipv4() == ipv4).map(|addr| addr.to_string()).collect();
        servers.join(",")
    };
    let search = config.dns_search.join(",");
    let ipv4 = join(true);
    let ipv6 = join(false);
    // the search domains go with the servers of IPv4, or of IPv6 when there are none
    let search_with_ipv6 = ipv4.is_empty() && !ipv6.is_empty();
    if !ipv4.is_empty() || !search_with_ipv6 {
        apply_dns(&guid, false, &ipv4, if search_with_ipv6 { "" } else { &search })?;
    }
    if !ipv6.is_empty() {
        apply_dns(&guid, true, &ipv6, if search_with_ipv6 { &search } else { "" })?;
    }
    Ok(())
}

fn apply_dns(guid: &GUID, ipv6: bool, servers: &str, search: &str) -> Result<(), String> {
    let mut servers = crate::win::wide(servers);
    let mut search_list = crate::win::wide(search);
    let mut settings: DNS_INTERFACE_SETTINGS = unsafe { zeroed() };
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = DNS_SETTING_NAMESERVER as u64;
    settings.NameServer = servers.as_mut_ptr();
    if !search.is_empty() {
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
    let address = to_sockaddr(endpoint);
    let mut index = 0u32;
    let result = unsafe { GetBestInterfaceEx(&address as *const _ as *const SOCKADDR, &mut index) };
    if result != NO_ERROR {
        return DEFAULT_MTU;
    }
    let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.InterfaceIndex = index;
    row.Family = if endpoint.is_ipv4() { AF_INET } else { AF_INET6 };
    if unsafe { GetIpInterfaceEntry(&mut row) } != NO_ERROR || row.NlMtu == 0 {
        return DEFAULT_MTU;
    }
    row.NlMtu.saturating_sub(OVERHEAD).clamp(MIN_IPV6_MTU, DEFAULT_MTU)
}
