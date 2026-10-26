// WireGuardNT, the WireGuard driver of Windows, through the API of wireguard.dll (wireguard.h of the
// wireguard-nt SDK). wireguard.dll is the one signed by WireGuard LLC, next to the exe, never changed.

use std::ffi::c_void;
use std::mem::{offset_of, size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr;
use std::sync::Arc;

use windows_sys::core::{BOOL, GUID};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, HMODULE};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::conf::{Config, Key};
use crate::log;
use crate::win::{from_wide_ptr, last_error, last_error_message, wide};

type AdapterHandle = *mut c_void;

const INTERFACE_HAS_PRIVATE_KEY: u32 = 1 << 1;
const INTERFACE_HAS_LISTEN_PORT: u32 = 1 << 2;
const INTERFACE_REPLACE_PEERS: u32 = 1 << 3;
const PEER_HAS_PUBLIC_KEY: u32 = 1 << 0;
const PEER_HAS_PRESHARED_KEY: u32 = 1 << 1;
const PEER_HAS_PERSISTENT_KEEPALIVE: u32 = 1 << 2;
const PEER_HAS_ENDPOINT: u32 = 1 << 3;
const PEER_REPLACE_ALLOWED_IPS: u32 = 1 << 5;
const PEER_UPDATE_ONLY: u32 = 1 << 7;
const ADAPTER_STATE_DOWN: i32 = 0;
const ADAPTER_STATE_UP: i32 = 1;
const ADAPTER_LOG_ON: i32 = 1;

#[repr(C, align(8))]
struct WgInterface {
    flags: u32,
    listen_port: u16,
    private_key: Key,
    public_key: Key,
    peers_count: u32,
}

#[repr(C, align(8))]
struct WgPeer {
    flags: u32,
    reserved: u32,
    public_key: Key,
    preshared_key: Key,
    persistent_keepalive: u16,
    endpoint: SOCKADDR_INET,
    tx_bytes: u64,
    rx_bytes: u64,
    last_handshake: u64,
    allowed_ips_count: u32,
}

#[repr(C, align(8))]
struct WgAllowedIp {
    address: [u8; 16],
    address_family: u16,
    cidr: u8,
    flags: u32,
}

// the layout of wireguard.h, the same on x64 and ARM64
const _: () = assert!(size_of::<WgInterface>() == 80);
const _: () = assert!(offset_of!(WgInterface, private_key) == 6);
const _: () = assert!(offset_of!(WgInterface, peers_count) == 72);
const _: () = assert!(size_of::<WgPeer>() == 136);
const _: () = assert!(offset_of!(WgPeer, persistent_keepalive) == 72);
const _: () = assert!(offset_of!(WgPeer, endpoint) == 76);
const _: () = assert!(offset_of!(WgPeer, tx_bytes) == 104);
const _: () = assert!(offset_of!(WgPeer, last_handshake) == 120);
const _: () = assert!(offset_of!(WgPeer, allowed_ips_count) == 128);
const _: () = assert!(size_of::<WgAllowedIp>() == 24);
const _: () = assert!(offset_of!(WgAllowedIp, address_family) == 16);
const _: () = assert!(offset_of!(WgAllowedIp, cidr) == 18);
const _: () = assert!(offset_of!(WgAllowedIp, flags) == 20);

type CreateAdapterFn = unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> AdapterHandle;
type CloseAdapterFn = unsafe extern "system" fn(AdapterHandle);
type DeleteDriverFn = unsafe extern "system" fn() -> BOOL;
type GetAdapterLuidFn = unsafe extern "system" fn(AdapterHandle, *mut NET_LUID_LH);
type GetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;
type LoggerCallback = unsafe extern "system" fn(i32, u64, *const u16);
type SetLoggerFn = unsafe extern "system" fn(Option<LoggerCallback>);
type SetAdapterLoggingFn = unsafe extern "system" fn(AdapterHandle, i32) -> BOOL;
type SetAdapterStateFn = unsafe extern "system" fn(AdapterHandle, i32) -> BOOL;
type SetConfigurationFn = unsafe extern "system" fn(AdapterHandle, *const WgInterface, u32) -> BOOL;
type GetConfigurationFn = unsafe extern "system" fn(AdapterHandle, *mut WgInterface, *mut u32) -> BOOL;

pub struct WireGuard {
    _module: HMODULE,
    create_adapter: CreateAdapterFn,
    close_adapter: CloseAdapterFn,
    delete_driver: DeleteDriverFn,
    get_adapter_luid: GetAdapterLuidFn,
    get_running_driver_version: GetRunningDriverVersionFn,
    set_adapter_logging: SetAdapterLoggingFn,
    set_adapter_state: SetAdapterStateFn,
    set_configuration: SetConfigurationFn,
    get_configuration: GetConfigurationFn,
}

// SAFETY: the functions of wireguard.dll can be called from any thread
unsafe impl Send for WireGuard {}
unsafe impl Sync for WireGuard {}

unsafe extern "system" fn logger(level: i32, _timestamp: u64, message: *const u16) {
    let text = from_wide_ptr(message);
    match level {
        1 => log!("wireguard: warning: {}", text),
        2 => log!("wireguard: error: {}", text),
        _ => log!("wireguard: {}", text),
    }
}

impl WireGuard {
    // wireguard.dll next to the exe: never one from another folder
    // (each transmute takes the type of the field it fills, the one of wireguard.h)
    #[allow(clippy::missing_transmute_annotations)]
    pub fn load() -> Result<Arc<WireGuard>, String> {
        let module = unsafe {
            LoadLibraryExW(
                wide("wireguard.dll").as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(format!("can't load wireguard.dll: {}", last_error_message()));
        }
        macro_rules! function {
            ($name:literal) => {{
                let address = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
                match address {
                    // SAFETY: the type is the one of wireguard.h
                    Some(address) => unsafe { std::mem::transmute(address) },
                    None => return Err(format!("wireguard.dll has no {}", $name)),
                }
            }};
        }
        let wireguard = WireGuard {
            _module: module,
            create_adapter: function!("WireGuardCreateAdapter"),
            close_adapter: function!("WireGuardCloseAdapter"),
            delete_driver: function!("WireGuardDeleteDriver"),
            get_adapter_luid: function!("WireGuardGetAdapterLUID"),
            get_running_driver_version: function!("WireGuardGetRunningDriverVersion"),
            set_adapter_logging: function!("WireGuardSetAdapterLogging"),
            set_adapter_state: function!("WireGuardSetAdapterState"),
            set_configuration: function!("WireGuardSetConfiguration"),
            get_configuration: function!("WireGuardGetConfiguration"),
        };
        let set_logger: SetLoggerFn = function!("WireGuardSetLogger");
        unsafe { set_logger(Some(logger)) };
        Ok(Arc::new(wireguard))
    }

    // "1.1", once an adapter is up
    pub fn driver_version(&self) -> Option<String> {
        let version = unsafe { (self.get_running_driver_version)() };
        if version == 0 {
            return None;
        }
        Some(format!("{}.{}", (version >> 16) & 0xff, version & 0xff))
    }

    // removes the driver when no adapter uses it anymore, for the uninstall
    pub fn delete_driver(&self) -> Result<(), String> {
        if unsafe { (self.delete_driver)() } == 0 {
            return Err(last_error_message());
        }
        Ok(())
    }
}

pub struct PeerStats {
    pub public_key: Key,
    pub endpoint: Option<SocketAddr>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    // FILETIME, 0 when never
    pub last_handshake: u64,
}

// A network adapter of WireGuardNT: it goes away with the adapter
pub struct Adapter {
    wireguard: Arc<WireGuard>,
    handle: AdapterHandle,
}

// SAFETY: the handle can be used from any thread, Adapter is used by one at a time
unsafe impl Send for Adapter {}

impl Adapter {
    // the GUID is the same at every connection, for Windows to know the network again
    pub fn create(wireguard: &Arc<WireGuard>, name: &str, kind: &str, guid: &GUID) -> Result<Adapter, String> {
        let handle = unsafe { (wireguard.create_adapter)(wide(name).as_ptr(), wide(kind).as_ptr(), guid) };
        if handle.is_null() {
            return Err(format!("can't create the network adapter: {}", last_error_message()));
        }
        let adapter = Adapter { wireguard: wireguard.clone(), handle };
        if unsafe { (wireguard.set_adapter_logging)(handle, ADAPTER_LOG_ON) } == 0 {
            log!("{}: no logs from the driver: {}", name, last_error_message());
        }
        Ok(adapter)
    }

    pub fn luid(&self) -> u64 {
        let mut luid = NET_LUID_LH { Value: 0 };
        unsafe {
            (self.wireguard.get_adapter_luid)(self.handle, &mut luid);
            luid.Value
        }
    }

    pub fn set_config(&self, config: &Config, endpoints: &[Option<SocketAddr>]) -> Result<(), String> {
        let mut buffer = build_config(config, endpoints);
        let bytes = (buffer.len() * 8) as u32;
        let ok = unsafe { (self.wireguard.set_configuration)(self.handle, buffer.as_ptr() as *const WgInterface, bytes) };
        let result = if ok == 0 { Err(format!("can't configure the tunnel: {}", last_error_message())) } else { Ok(()) };
        wipe(&mut buffer);
        result
    }

    // another address for a server: the rest stays as it is, its session included
    pub fn set_endpoint(&self, public_key: &Key, endpoint: &SocketAddr) -> Result<(), String> {
        let buffer = build_endpoint(public_key, endpoint);
        let bytes = (buffer.len() * 8) as u32;
        let ok = unsafe { (self.wireguard.set_configuration)(self.handle, buffer.as_ptr() as *const WgInterface, bytes) };
        if ok == 0 {
            return Err(format!("can't change the address of the server: {}", last_error_message()));
        }
        Ok(())
    }

    pub fn set_up(&self, up: bool) -> Result<(), String> {
        let state = if up { ADAPTER_STATE_UP } else { ADAPTER_STATE_DOWN };
        if unsafe { (self.wireguard.set_adapter_state)(self.handle, state) } == 0 {
            return Err(format!("can't turn the tunnel {}: {}", if up { "on" } else { "off" }, last_error_message()));
        }
        Ok(())
    }

    pub fn peers(&self) -> Result<Vec<PeerStats>, String> {
        let mut size: u32 = 4096;
        loop {
            let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
            let mut bytes = (buffer.len() * 8) as u32;
            let ok = unsafe {
                (self.wireguard.get_configuration)(self.handle, buffer.as_mut_ptr() as *mut WgInterface, &mut bytes)
            };
            if ok == 0 {
                let code = last_error();
                if code == ERROR_MORE_DATA && bytes > size {
                    size = bytes;
                    continue;
                }
                return Err(format!("can't read the tunnel: {}", crate::win::error_message(code)));
            }
            let peers = parse_peers(&buffer, bytes as usize);
            // it holds the private key
            wipe(&mut buffer);
            return Ok(peers);
        }
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        // also removes the adapter, with its addresses and routes
        unsafe { (self.wireguard.close_adapter)(self.handle) };
    }
}

fn wipe(buffer: &mut [u64]) {
    for item in buffer.iter_mut() {
        unsafe { ptr::write_volatile(item, 0) };
    }
}

pub fn to_sockaddr(address: &SocketAddr) -> SOCKADDR_INET {
    let mut result: SOCKADDR_INET = unsafe { zeroed() };
    match address {
        SocketAddr::V4(address) => {
            result.Ipv4.sin_family = AF_INET;
            result.Ipv4.sin_port = address.port().to_be();
            result.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.ip().octets());
        }
        SocketAddr::V6(address) => {
            result.Ipv6.sin6_family = AF_INET6;
            result.Ipv6.sin6_port = address.port().to_be();
            result.Ipv6.sin6_flowinfo = address.flowinfo();
            result.Ipv6.sin6_addr.u.Byte = address.ip().octets();
            result.Ipv6.Anonymous.sin6_scope_id = address.scope_id();
        }
    }
    result
}

pub fn ip_sockaddr(address: IpAddr) -> SOCKADDR_INET {
    to_sockaddr(&SocketAddr::new(address, 0))
}

pub fn from_sockaddr(address: &SOCKADDR_INET) -> Option<SocketAddr> {
    unsafe {
        match address.si_family {
            AF_INET => {
                let ip = Ipv4Addr::from(address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
                Some(SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(address.Ipv4.sin_port))))
            }
            AF_INET6 => {
                let ip = Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    u16::from_be(address.Ipv6.sin6_port),
                    address.Ipv6.sin6_flowinfo,
                    address.Ipv6.Anonymous.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

// The configuration as WireGuardSetConfiguration wants it: the interface, then each peer followed by its
// allowed IPs. Every struct is 8-aligned and a multiple of 8 long, hence a buffer of u64.
fn build_config(config: &Config, endpoints: &[Option<SocketAddr>]) -> Vec<u64> {
    let allowed_ips: usize = config.peers.iter().map(|peer| peer.allowed_ips.len()).sum();
    let bytes = size_of::<WgInterface>() + config.peers.len() * size_of::<WgPeer>() + allowed_ips * size_of::<WgAllowedIp>();
    let mut buffer = vec![0u64; bytes / 8];
    let base = buffer.as_mut_ptr() as *mut u8;
    // SAFETY: the buffer is zeroed, 8-aligned and as long as the structs written in it
    unsafe {
        let interface = &mut *(base as *mut WgInterface);
        interface.flags = INTERFACE_HAS_PRIVATE_KEY | INTERFACE_REPLACE_PEERS;
        if config.listen_port != 0 {
            interface.flags |= INTERFACE_HAS_LISTEN_PORT;
            interface.listen_port = config.listen_port;
        }
        interface.private_key = config.private_key;
        interface.peers_count = config.peers.len() as u32;
        let mut offset = size_of::<WgInterface>();
        for (index, peer) in config.peers.iter().enumerate() {
            let item = &mut *(base.add(offset) as *mut WgPeer);
            item.flags = PEER_HAS_PUBLIC_KEY | PEER_REPLACE_ALLOWED_IPS | PEER_HAS_PERSISTENT_KEEPALIVE;
            item.public_key = peer.public_key;
            if let Some(key) = peer.preshared_key {
                item.flags |= PEER_HAS_PRESHARED_KEY;
                item.preshared_key = key;
            }
            item.persistent_keepalive = peer.keepalive;
            if let Some(Some(endpoint)) = endpoints.get(index) {
                item.flags |= PEER_HAS_ENDPOINT;
                item.endpoint = to_sockaddr(endpoint);
            }
            item.allowed_ips_count = peer.allowed_ips.len() as u32;
            offset += size_of::<WgPeer>();
            for net in &peer.allowed_ips {
                let allowed = &mut *(base.add(offset) as *mut WgAllowedIp);
                match net.addr {
                    IpAddr::V4(addr) => {
                        allowed.address_family = AF_INET;
                        allowed.address[..4].copy_from_slice(&addr.octets());
                    }
                    IpAddr::V6(addr) => {
                        allowed.address_family = AF_INET6;
                        allowed.address = addr.octets();
                    }
                }
                allowed.cidr = net.prefix;
                offset += size_of::<WgAllowedIp>();
            }
        }
        debug_assert_eq!(offset, bytes);
    }
    buffer
}

// The interface with no flag, so nothing of it changes, and the one peer, only if it's there
fn build_endpoint(public_key: &Key, endpoint: &SocketAddr) -> Vec<u64> {
    let mut buffer = vec![0u64; (size_of::<WgInterface>() + size_of::<WgPeer>()) / 8];
    let base = buffer.as_mut_ptr() as *mut u8;
    // SAFETY: the buffer is zeroed, 8-aligned and as long as the two structs
    unsafe {
        let interface = &mut *(base as *mut WgInterface);
        interface.peers_count = 1;
        let peer = &mut *(base.add(size_of::<WgInterface>()) as *mut WgPeer);
        peer.flags = PEER_HAS_PUBLIC_KEY | PEER_HAS_ENDPOINT | PEER_UPDATE_ONLY;
        peer.public_key = *public_key;
        peer.endpoint = to_sockaddr(endpoint);
    }
    buffer
}

fn parse_peers(buffer: &[u64], bytes: usize) -> Vec<PeerStats> {
    let bytes = bytes.min(buffer.len() * 8);
    let base = buffer.as_ptr() as *const u8;
    let mut peers = Vec::new();
    if bytes < size_of::<WgInterface>() {
        return peers;
    }
    // SAFETY: every read stays within the bytes written by the driver
    unsafe {
        let interface = &*(base as *const WgInterface);
        let mut offset = size_of::<WgInterface>();
        for _ in 0..interface.peers_count {
            if offset + size_of::<WgPeer>() > bytes {
                break;
            }
            let peer = &*(base.add(offset) as *const WgPeer);
            peers.push(PeerStats {
                public_key: peer.public_key,
                endpoint: if peer.flags & PEER_HAS_ENDPOINT != 0 { from_sockaddr(&peer.endpoint) } else { None },
                tx_bytes: peer.tx_bytes,
                rx_bytes: peer.rx_bytes,
                last_handshake: peer.last_handshake,
            });
            offset += size_of::<WgPeer>() + peer.allowed_ips_count as usize * size_of::<WgAllowedIp>();
        }
    }
    peers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conf;

    #[test]
    fn the_configuration_for_the_driver() {
        let text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nListenPort = 51000\n\
                    Address = 10.103.1.2\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
                    AllowedIPs = 10.103.1.0/24, fd00::/64\nEndpoint = 203.0.113.1:51820\nPersistentKeepalive = 25\n";
        let config = conf::parse(text).unwrap();
        let endpoint: SocketAddr = "203.0.113.1:51820".parse().unwrap();
        let buffer = build_config(&config, &[Some(endpoint)]);
        assert_eq!(buffer.len() * 8, 80 + 136 + 2 * 24);
        let base = buffer.as_ptr() as *const u8;
        unsafe {
            let interface = &*(base as *const WgInterface);
            assert_eq!(interface.flags, INTERFACE_HAS_PRIVATE_KEY | INTERFACE_REPLACE_PEERS | INTERFACE_HAS_LISTEN_PORT);
            assert_eq!(interface.listen_port, 51000);
            assert_eq!(interface.private_key, config.private_key);
            assert_eq!(interface.peers_count, 1);
            let peer = &*(base.add(80) as *const WgPeer);
            assert_eq!(peer.flags & PEER_HAS_ENDPOINT, PEER_HAS_ENDPOINT);
            assert_eq!(peer.flags & PEER_HAS_PRESHARED_KEY, 0);
            assert_eq!(peer.persistent_keepalive, 25);
            assert_eq!(from_sockaddr(&peer.endpoint), Some(endpoint));
            assert_eq!(peer.allowed_ips_count, 2);
            // the port in network order
            assert_eq!(*base.add(80 + 76 + 2), 0xca);
            assert_eq!(*base.add(80 + 76 + 3), 0x6c);
            let first = &*(base.add(80 + 136) as *const WgAllowedIp);
            assert_eq!((first.address_family, first.cidr, &first.address[..4]), (AF_INET, 24, &[10, 103, 1, 0][..]));
            let second = &*(base.add(80 + 136 + 24) as *const WgAllowedIp);
            assert_eq!((second.address_family, second.cidr, second.address[0]), (AF_INET6, 64, 0xfd));
        }
        let peers = parse_peers(&buffer, buffer.len() * 8);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, config.peers[0].public_key);
        assert_eq!(peers[0].endpoint, Some(endpoint));
        // a buffer cut short reads no peer
        assert_eq!(parse_peers(&buffer, 100).len(), 0);
    }

    #[test]
    fn another_address() {
        let key = conf::parse_key("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap();
        let endpoint: SocketAddr = "[2001:db8::2]:51821".parse().unwrap();
        let buffer = build_endpoint(&key, &endpoint);
        assert_eq!(buffer.len() * 8, 80 + 136);
        let base = buffer.as_ptr() as *const u8;
        unsafe {
            let interface = &*(base as *const WgInterface);
            // no key, port or peers replaced
            assert_eq!((interface.flags, interface.peers_count, interface.private_key), (0, 1, [0; 32]));
            let peer = &*(base.add(80) as *const WgPeer);
            assert_eq!(peer.flags, PEER_HAS_PUBLIC_KEY | PEER_HAS_ENDPOINT | PEER_UPDATE_ONLY);
            assert_eq!(peer.flags, 0b1000_1001);
            assert_eq!((peer.public_key, peer.allowed_ips_count, peer.persistent_keepalive), (key, 0, 0));
            assert_eq!(from_sockaddr(&peer.endpoint), Some(endpoint));
        }
    }

    #[test]
    fn socket_addresses() {
        for text in ["192.0.2.7:51820", "[2001:db8::7]:443"] {
            let address: SocketAddr = text.parse().unwrap();
            assert_eq!(from_sockaddr(&to_sockaddr(&address)), Some(address));
        }
    }
}
