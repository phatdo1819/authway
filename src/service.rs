// The Windows service, as SYSTEM: it keeps the configurations of the tunnels and turns them on and off for the
// app of the users, through its named pipe. A tunnel is turned off when the user who turned it on signs out.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::net::SocketAddr;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Instant;

use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, NO_ERROR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, RevertToSelf, WinBuiltinAdministratorsSid, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientSessionId, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::RemoteDesktop::WTSSESSION_NOTIFICATION;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW, SERVICE_ACCEPT_SESSIONCHANGE,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SESSIONCHANGE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows_sys::Win32::UI::WindowsAndMessaging::WTS_SESSION_LOGOFF;

use crate::api::Page;
use crate::conf::{self, Config};
use crate::failover::{self, Failover, Next, Poll};
use crate::ipc::{self, PeerInfo, Request, Response, TunnelInfo};
use crate::log;
use crate::names;
use crate::settings;
use crate::store;
use crate::wg::PeerStats;
use crate::win::{error_message, filetime_to_unix, last_error, last_error_message, unix_now, wide, Handle};

// SYSTEM and the administrators; the users who are signed in on the computer can read and write, but not create
// instances of the pipe (FILE_CREATE_PIPE_INSTANCE): no other program can answer in place of the service
#[cfg(not(feature = "testing"))]
const PIPE_SECURITY: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";
#[cfg(feature = "testing")]
const PIPE_SECURITY: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";

trait Tunnel: Send {
    // the counters of each server, as the driver has them
    fn peers(&self) -> Vec<PeerStats>;
    fn mtu(&self) -> u32;
    // another address for a server, a fallback
    fn set_endpoint(&mut self, public_key: &conf::Key, address: SocketAddr) -> Result<(), String>;
}

// a tunnel that is on, and its addresses for each server
type Started = (Box<dyn Tunnel>, Vec<Option<Failover>>);

struct Active {
    tunnel: Box<dyn Tunnel>,
    since: u64,
    // the Windows session of the user who turned it on
    session: u32,
    // of this connection: a change of address asked for an earlier one doesn't apply
    id: u64,
    // for each server of the configuration, None for one without Endpoint
    failovers: Vec<Option<Failover>>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

// A change of address that the watch asks for, made out of the lock of the manager: a lookup can take seconds
struct Switch {
    tunnel: String,
    id: u64,
    peer: usize,
    next: Next,
}

struct Entry {
    name: String,
    guid: GUID,
    config: Config,
    // of the private key, for the details
    public_key: String,
    active: Option<Active>,
}

impl Entry {
    fn new(name: String, guid: GUID, config: Config) -> Entry {
        let public_key = conf::encode_key(&crate::x25519::public_key(&config.private_key));
        Entry { name, guid, config, public_key, active: None }
    }
}

struct Manager {
    entries: Vec<Entry>,
    #[cfg(not(feature = "testing"))]
    wireguard: Option<Arc<crate::wg::WireGuard>>,
}

struct Client {
    session: u32,
    can_manage: bool,
}

impl Manager {
    fn load() -> Manager {
        let mut entries = Vec::new();
        for stored in store::list() {
            match conf::parse(&stored.text) {
                Ok(config) => entries.push(Entry::new(stored.name, stored.guid, config)),
                Err(error) => log!("{}: the configuration isn't valid anymore: {}", stored.name, error),
            }
        }
        log!("{} tunnels", entries.len());
        Manager {
            entries,
            #[cfg(not(feature = "testing"))]
            wireguard: None,
        }
    }

    fn find(&mut self, name: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|entry| entry.name.eq_ignore_ascii_case(name))
    }

    fn list(&self) -> Vec<TunnelInfo> {
        self.entries.iter().map(info).collect()
    }

    fn up(&mut self, name: &str, session: u32) -> Response {
        let tunnel = match self.find(name) {
            None => return Response::failure(ipc::NOT_FOUND, format!("There's no VPN named {}.", name)),
            Some(entry) if entry.active.is_some() => return Response::success(),
            Some(entry) => start(&entry.name, &entry.guid, &entry.config),
        };
        #[cfg(not(feature = "testing"))]
        let tunnel = tunnel(&mut self.wireguard);
        let entry = self.find(name).expect("the entry");
        match tunnel {
            Ok((tunnel, failovers)) => {
                log!("{}: on, for the session {}", entry.name, session);
                entry.active = Some(Active { tunnel, since: unix_now(), session, id: next_id(), failovers });
                Response::success()
            }
            Err(error) => {
                log!("{}: can't turn on: {}", entry.name, error);
                Response::failure(ipc::FAILED, error)
            }
        }
    }

    fn down(&mut self, name: &str) -> Response {
        match self.find(name) {
            None => Response::failure(ipc::NOT_FOUND, format!("There's no VPN named {}.", name)),
            Some(entry) => {
                if entry.active.take().is_some() {
                    log!("{}: off", entry.name);
                }
                Response::success()
            }
        }
    }

    fn import(&mut self, name: &str, text: &str, replace: bool) -> Response {
        if !conf::is_valid_name(name) {
            return Response::failure(ipc::INVALID, format!("\"{}\" can't be the name of a VPN.", name));
        }
        let config = match conf::parse(text) {
            Ok(config) => config,
            Err(error) => return Response::failure(ipc::INVALID, format!("This isn't a valid configuration: {}.", error)),
        };
        if let Some(login) = &config.login {
            match Page::parse(login) {
                None => {
                    return Response::failure(ipc::INVALID, format!("The login page {} isn't an address of the VPN.", login))
                }
                // the passwords go only through the tunnel
                Some(page) if !config.routes_to(page.host.into()) => {
                    return Response::failure(
                        ipc::INVALID,
                        format!("The login page {} isn't reached through the VPN.", page),
                    )
                }
                Some(_) => {}
            }
        }
        let existing = self.entries.iter().position(|entry| entry.name.eq_ignore_ascii_case(name));
        if existing.is_some() && !replace {
            return Response::failure(ipc::EXISTS, format!("There's already a VPN named {}.", name));
        }
        if let Some(index) = existing {
            // its key keeps the first spelling of the name
            let entry = self.entries.remove(index);
            if entry.active.is_some() {
                log!("{}: off, to be replaced", entry.name);
            }
            if entry.name != name {
                let _ = store::delete(&entry.name);
            }
        }
        match store::save(name, text) {
            Ok(stored) => {
                log!("{}: {}", name, if existing.is_some() { "replaced" } else { "added" });
                for ignored in &config.ignored {
                    log!("{}: {} is ignored", name, ignored);
                }
                self.entries.push(Entry::new(stored.name, stored.guid, config));
                self.entries.sort_by_key(|entry| entry.name.to_lowercase());
                Response::success()
            }
            Err(error) => {
                log!("{}: can't save: {}", name, error);
                Response::failure(ipc::FAILED, format!("Can't save the configuration: {}.", error))
            }
        }
    }

    fn remove(&mut self, name: &str) -> Response {
        let Some(index) = self.entries.iter().position(|entry| entry.name.eq_ignore_ascii_case(name)) else {
            return Response::failure(ipc::NOT_FOUND, format!("There's no VPN named {}.", name));
        };
        let entry = self.entries.remove(index);
        drop(entry.active);
        match store::delete(&entry.name) {
            Ok(()) => {
                log!("{}: removed", entry.name);
                Response::success()
            }
            Err(error) => Response::failure(ipc::FAILED, format!("Can't remove the configuration: {}.", error)),
        }
    }

    fn session_ended(&mut self, session: u32) {
        for entry in &mut self.entries {
            if entry.active.as_ref().is_some_and(|active| active.session == session) {
                log!("{}: off, the user signed out", entry.name);
                entry.active = None;
            }
        }
    }

    fn stop(&mut self) {
        for entry in &mut self.entries {
            if entry.active.take().is_some() {
                log!("{}: off, the service stops", entry.name);
            }
        }
    }

    // every POLL: whether the servers of the tunnels that are on still answer
    fn watch(&mut self, now: Instant) -> Vec<Switch> {
        let mut switches = Vec::new();
        for entry in &mut self.entries {
            let Some(active) = &mut entry.active else { continue };
            if active.failovers.iter().all(Option::is_none) {
                continue;
            }
            let stats = active.tunnel.peers();
            for (index, failover) in active.failovers.iter_mut().enumerate() {
                let Some(failover) = failover else { continue };
                let key = entry.config.peers[index].public_key;
                let Some(stats) = stats.iter().find(|stats| stats.public_key == key) else { continue };
                match failover.poll(now, stats.rx_bytes, stats.tx_bytes) {
                    (Poll::Answered, _) => log!("{}: {} answers", entry.name, failover.endpoint()),
                    (_, Some(next)) => {
                        switches.push(Switch { tunnel: entry.name.clone(), id: active.id, peer: index, next })
                    }
                    _ => {}
                }
            }
        }
        switches
    }

    // the address found for the switch, None when it can't be found
    fn switch(&mut self, switch: Switch, address: Option<SocketAddr>) {
        let Some(entry) = self.find(&switch.tunnel) else { return };
        let Some(active) = entry.active.as_mut().filter(|active| active.id == switch.id) else { return };
        let Some(Some(failover)) = active.failovers.get_mut(switch.peer) else { return };
        let key = entry.config.peers[switch.peer].public_key;
        let before = failover.endpoint().to_string();
        let Next { index, endpoint, .. } = switch.next;
        let Some(address) = address else {
            log!("{}: no answer from {}, and {} can't be found", entry.name, before, endpoint);
            failover.moved(index, None);
            return;
        };
        if index == failover.index() && address == failover.address() {
            // the same name at the same address: nothing to change
            failover.moved(index, Some(address));
            return;
        }
        match active.tunnel.set_endpoint(&key, address) {
            Ok(()) => {
                failover.moved(index, Some(address));
                let seconds = failover::SILENCE.as_secs();
                log!("{}: no answer from {} for {} seconds, now {} ({})", entry.name, before, seconds, endpoint, address);
            }
            Err(error) => {
                log!("{}: {}", entry.name, error);
                failover.refused();
            }
        }
    }

    fn handle(&mut self, request: Request, client: &Client) -> Response {
        let denied = || {
            Response::failure(ipc::ACCESS_DENIED, "Only an administrator can add or remove a VPN on this computer.")
        };
        match request {
            Request::List => {
                Response { ok: true, tunnels: self.list(), can_manage: client.can_manage, ..Response::default() }
            }
            Request::Up { name } => self.up(&name, client.session),
            Request::Down { name } => self.down(&name),
            Request::Import { name, config, replace } => {
                if !client.can_manage {
                    return denied();
                }
                self.import(&name, &config, replace)
            }
            Request::Remove { name } => {
                if !client.can_manage {
                    return denied();
                }
                self.remove(&name)
            }
        }
    }
}

fn info(entry: &Entry) -> TunnelInfo {
    let config = &entry.config;
    let active = entry.active.as_ref();
    let stats = active.map(|active| active.tunnel.peers()).unwrap_or_default();
    let peers: Vec<PeerInfo> = config
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            let now = stats.iter().find(|stats| stats.public_key == peer.public_key);
            let failover = active.and_then(|active| active.failovers.get(index)).and_then(Option::as_ref);
            PeerInfo {
                name: peer.name.clone(),
                public_key: conf::encode_key(&peer.public_key),
                preshared_key: peer.preshared_key.is_some(),
                endpoint: peer.endpoint.as_ref().map(ToString::to_string).unwrap_or_default(),
                fallbacks: peer.fallbacks.iter().map(ToString::to_string).collect(),
                in_use: failover.map(|failover| failover.endpoint().to_string()).unwrap_or_default(),
                address: now.and_then(|now| now.endpoint).map(|address| address.to_string()).unwrap_or_default(),
                allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
                keepalive: peer.keepalive,
                handshake: now.map_or(0, |now| filetime_to_unix(now.last_handshake)),
                rx_bytes: now.map_or(0, |now| now.rx_bytes),
                tx_bytes: now.map_or(0, |now| now.tx_bytes),
            }
        })
        .collect();
    TunnelInfo {
        name: entry.name.clone(),
        up: entry.active.is_some(),
        login: config.login.clone(),
        server: config.server_name().map(str::to_string),
        endpoint: peers
            .iter()
            .find(|peer| !peer.endpoint.is_empty())
            .map(|peer| if peer.in_use.is_empty() { &peer.endpoint } else { &peer.in_use })
            .cloned()
            .unwrap_or_default(),
        addresses: config.addresses.iter().map(ToString::to_string).collect(),
        routes: config.routes().iter().map(ToString::to_string).collect(),
        since: active.map_or(0, |active| active.since),
        handshake: peers.iter().map(|peer| peer.handshake).max().unwrap_or(0),
        rx_bytes: peers.iter().map(|peer| peer.rx_bytes).sum(),
        tx_bytes: peers.iter().map(|peer| peer.tx_bytes).sum(),
        public_key: entry.public_key.clone(),
        device: config.name.clone(),
        listen_port: config.listen_port,
        dns: config.dns.iter().map(ToString::to_string).collect(),
        dns_search: config.dns_search.clone(),
        mtu: config.mtu.map_or(0, u32::from),
        mtu_in_use: active.map_or(0, |active| active.tunnel.mtu()),
        peers,
    }
}

// the address of each server: the one of its Endpoint, or of the first fallback that can be found
fn resolve(name: &str, config: &Config) -> Result<Vec<Option<Failover>>, String> {
    let failovers = config.peers.iter().map(Failover::start).collect::<Result<Vec<_>, _>>()?;
    for failover in failovers.iter().flatten().filter(|failover| failover.index() > 0) {
        log!("{}: the endpoint can't be found, fallback {} instead: {}", name, failover.index(), failover.endpoint());
    }
    Ok(failovers)
}

#[cfg(not(feature = "testing"))]
struct DriverTunnel {
    adapter: crate::wg::Adapter,
    mtu: u32,
}

#[cfg(not(feature = "testing"))]
impl Tunnel for DriverTunnel {
    fn peers(&self) -> Vec<PeerStats> {
        self.adapter.peers().unwrap_or_default()
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn set_endpoint(&mut self, public_key: &conf::Key, address: SocketAddr) -> Result<(), String> {
        self.adapter.set_endpoint(public_key, &address)
    }
}

// The steps that don't need the driver, then a function that turns the tunnel on with it
#[cfg(not(feature = "testing"))]
fn start(
    name: &str,
    guid: &GUID,
    config: &Config,
) -> impl FnOnce(&mut Option<Arc<crate::wg::WireGuard>>) -> Result<Started, String> {
    let name = name.to_string();
    let guid = *guid;
    let config = config.clone();
    move |wireguard| {
        use crate::{net, wg};
        let failovers = resolve(&name, &config)?;
        let endpoints: Vec<Option<SocketAddr>> =
            failovers.iter().map(|failover| failover.as_ref().map(Failover::address)).collect();
        if wireguard.is_none() {
            *wireguard = Some(wg::WireGuard::load()?);
        }
        let wireguard = wireguard.as_ref().expect("loaded");
        let adapter = wg::Adapter::create(wireguard, &name, names::PRODUCT, &guid)?;
        let mtu = match config.mtu {
            Some(mtu) => mtu as u32,
            None => endpoints.iter().flatten().next().map(net::auto_mtu).unwrap_or(net::DEFAULT_MTU),
        };
        net::configure(adapter.luid(), &config, mtu)?;
        adapter.set_config(&config, &endpoints)?;
        adapter.set_up(true)?;
        let servers: Vec<String> = endpoints.iter().flatten().map(ToString::to_string).collect();
        log!(
            "{}: to {}, MTU {}, driver {}",
            name,
            servers.join(", "),
            mtu,
            wireguard.driver_version().unwrap_or_else(|| "?".to_string())
        );
        Ok((Box::new(DriverTunnel { adapter, mtu }) as Box<dyn Tunnel>, failovers))
    }
}

// The tests: no driver. Each server sends a handshake and answers every second, from one second after the start,
// at any address but the port DEAD_PORT, where only this computer sends.
#[cfg(feature = "testing")]
const DEAD_PORT: u16 = 9;

#[cfg(feature = "testing")]
struct FakePeer {
    key: conf::Key,
    endpoint: Option<SocketAddr>,
    rx: u64,
    tx: u64,
    // FILETIME
    handshake: u64,
    // seconds since 1970, of the last count
    at: u64,
}

#[cfg(feature = "testing")]
struct FakeTunnel {
    peers: Mutex<Vec<FakePeer>>,
    mtu: u32,
}

#[cfg(feature = "testing")]
impl Tunnel for FakeTunnel {
    fn peers(&self) -> Vec<PeerStats> {
        let now = unix_now();
        let mut peers = self.peers.lock().unwrap_or_else(|error| error.into_inner());
        peers
            .iter_mut()
            .map(|peer| {
                let seconds = now.saturating_sub(peer.at);
                peer.at = now;
                if let Some(endpoint) = peer.endpoint.filter(|_| seconds > 0) {
                    peer.tx += 148 * seconds;
                    if endpoint.port() != DEAD_PORT {
                        peer.rx += 92 * seconds;
                        peer.handshake = (now + 11_644_473_600) * 10_000_000;
                    }
                }
                PeerStats {
                    public_key: peer.key,
                    endpoint: peer.endpoint,
                    tx_bytes: peer.tx,
                    rx_bytes: peer.rx,
                    last_handshake: peer.handshake,
                }
            })
            .collect()
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn set_endpoint(&mut self, public_key: &conf::Key, address: SocketAddr) -> Result<(), String> {
        let peers = self.peers.get_mut().unwrap_or_else(|error| error.into_inner());
        let peer = peers.iter_mut().find(|peer| peer.key == *public_key).ok_or("no such server")?;
        peer.endpoint = Some(address);
        Ok(())
    }
}

#[cfg(feature = "testing")]
fn start(name: &str, _guid: &GUID, config: &Config) -> Result<Started, String> {
    let failovers = resolve(name, config)?;
    let now = unix_now();
    let peers = config
        .peers
        .iter()
        .zip(&failovers)
        .map(|(peer, failover)| FakePeer {
            key: peer.public_key,
            endpoint: failover.as_ref().map(Failover::address),
            rx: 0,
            tx: 0,
            handshake: 0,
            at: now,
        })
        .collect();
    let tunnel = FakeTunnel { peers: Mutex::new(peers), mtu: config.mtu.map_or(crate::net::DEFAULT_MTU, u32::from) };
    Ok((Box::new(tunnel), failovers))
}

fn is_administrator(pipe: HANDLE) -> bool {
    unsafe {
        // the client allows only its identification: enough to read its groups
        if ImpersonateNamedPipeClient(pipe) == 0 {
            return false;
        }
        let mut token: HANDLE = ptr::null_mut();
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
        RevertToSelf();
        if opened == 0 {
            return false;
        }
        let token = Handle(token);
        let mut sid = [0u8; 68];
        let mut size = sid.len() as u32;
        if CreateWellKnownSid(WinBuiltinAdministratorsSid, ptr::null_mut(), sid.as_mut_ptr() as _, &mut size) == 0 {
            return false;
        }
        let mut member = 0;
        // without elevation the token of an administrator has the group only to deny
        CheckTokenMembership(token.0, sid.as_mut_ptr() as _, &mut member) != 0 && member != 0
    }
}

fn client_of(pipe: HANDLE) -> Client {
    let mut session = u32::MAX;
    unsafe { GetNamedPipeClientSessionId(pipe, &mut session) };
    let can_manage = if cfg!(feature = "testing") {
        std::env::var("AUTHWAY_TEST_DENY").is_err()
    } else {
        is_administrator(pipe) || settings::users_can_manage()
    };
    Client { session, can_manage }
}

struct Server {
    manager: Mutex<Manager>,
    stopping: AtomicBool,
}

impl Server {
    fn serve_client(&self, pipe: Handle) {
        let response = match ipc::read_message::<Request>(pipe.0) {
            Ok(request) => {
                let client = client_of(pipe.0);
                let mut manager = self.manager.lock().unwrap_or_else(|error| error.into_inner());
                manager.handle(request, &client)
            }
            Err(error) => Response::failure(ipc::INVALID, error),
        };
        if let Err(error) = ipc::write_message(pipe.0, &response) {
            log!("{}", error);
        }
        unsafe {
            FlushFileBuffers(pipe.0);
            DisconnectNamedPipe(pipe.0);
        }
    }

    // a connection per request, each on its own thread
    fn listen(self: Arc<Self>) {
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(PIPE_SECURITY).as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            log!("can't make the security of the pipe: {}", last_error_message());
            return;
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let name = wide(&names::pipe());
        let mut first = true;
        while !self.stopping.load(Ordering::SeqCst) {
            let mode = if first { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX };
            let pipe = Handle(unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    mode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    64 * 1024,
                    64 * 1024,
                    0,
                    &attributes,
                )
            });
            if !pipe.is_valid() {
                log!("can't create the pipe: {}", last_error_message());
                if first {
                    // another program has it
                    return;
                }
                thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
            first = false;
            let connected = unsafe { ConnectNamedPipe(pipe.0, ptr::null_mut()) } != 0 || last_error() == ERROR_PIPE_CONNECTED;
            if self.stopping.load(Ordering::SeqCst) {
                break;
            }
            if !connected {
                continue;
            }
            let server = self.clone();
            thread::spawn(move || server.serve_client(pipe));
        }
        unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor as _) };
    }

    // the fallbacks of the servers that stop answering, until the service stops
    fn watch(&self) {
        while !self.stopping.load(Ordering::SeqCst) {
            thread::sleep(failover::POLL);
            let switches = self.manager.lock().unwrap_or_else(|error| error.into_inner()).watch(Instant::now());
            for switch in switches {
                // out of the lock, the app gets its answers meanwhile; the last address when it can't be found
                let address = failover::lookup(&switch.next.endpoint, failover::LOOKUP_TIME).or(switch.next.known);
                self.manager.lock().unwrap_or_else(|error| error.into_inner()).switch(switch, address);
            }
        }
    }

    // the pipe waits for a connection: one wakes it up
    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _wake = Handle(unsafe {
            CreateFileW(
                wide(&names::pipe()).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        });
        self.manager.lock().unwrap_or_else(|error| error.into_inner()).stop();
    }
}

enum Control {
    Stop,
    SignedOut(u32),
}

static CONTROL: OnceLock<Mutex<Sender<Control>>> = OnceLock::new();

unsafe extern "system" fn control_handler(control: u32, event: u32, data: *mut c_void, _context: *mut c_void) -> u32 {
    let send = |message| {
        if let Some(sender) = CONTROL.get() {
            let _ = sender.lock().unwrap_or_else(|error| error.into_inner()).send(message);
        }
    };
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            send(Control::Stop);
            NO_ERROR
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            if event == WTS_SESSION_LOGOFF && !data.is_null() {
                let notification = &*(data as *const WTSSESSION_NOTIFICATION);
                send(Control::SignedOut(notification.dwSessionId));
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn set_status(handle: SERVICE_STATUS_HANDLE, state: SERVICE_STATUS_CURRENT_STATE, accepted: u32, exit_code: u32) {
    let mut status: SERVICE_STATUS = unsafe { zeroed() };
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = accepted;
    status.dwWin32ExitCode = exit_code;
    status.dwWaitHint = if state == SERVICE_RUNNING || state == SERVICE_STOPPED { 0 } else { 10_000 };
    unsafe { SetServiceStatus(handle, &status) };
}

pub fn log_path() -> std::path::PathBuf {
    crate::win::exe_dir().join("log").join("service.log")
}

unsafe extern "system" fn service_main(_count: u32, _arguments: *mut PWSTR) {
    log::init(log_path());
    let (sender, receiver) = mpsc::channel();
    let _ = CONTROL.set(Mutex::new(sender));
    let handle = RegisterServiceCtrlHandlerExW(wide(names::SERVICE_NAME).as_ptr(), Some(control_handler), ptr::null());
    if handle.is_null() {
        log!("can't register the service: {}", last_error_message());
        return;
    }
    set_status(handle, SERVICE_START_PENDING, 0, NO_ERROR);
    log!("{} {}: service started", names::PRODUCT, names::VERSION);
    let server = Arc::new(Server { manager: Mutex::new(Manager::load()), stopping: AtomicBool::new(false) });
    let listener = {
        let server = server.clone();
        thread::spawn(move || server.listen())
    };
    let watcher = {
        let server = server.clone();
        thread::spawn(move || server.watch())
    };
    set_status(
        handle,
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE,
        NO_ERROR,
    );
    while let Ok(control) = receiver.recv() {
        match control {
            Control::Stop => break,
            Control::SignedOut(session) => {
                server.manager.lock().unwrap_or_else(|error| error.into_inner()).session_ended(session)
            }
        }
    }
    set_status(handle, SERVICE_STOP_PENDING, 0, NO_ERROR);
    server.stop();
    let _ = listener.join();
    let _ = watcher.join();
    log!("service stopped");
    set_status(handle, SERVICE_STOPPED, 0, NO_ERROR);
}

// Called by the service manager: --service
pub fn run() -> i32 {
    let name = wide(names::SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_ptr() as *mut u16, lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: ptr::null_mut(), lpServiceProc: None },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        eprintln!("this is the service of {}: {}", names::PRODUCT, error_message(last_error()));
        return 1;
    }
    0
}

// The service as the user, with fake tunnels, for the tests: until the process is ended
#[cfg(feature = "testing")]
pub fn run_console() -> i32 {
    log::init(log_path());
    log!("{} {}: test service started", names::PRODUCT, names::VERSION);
    let server = Arc::new(Server { manager: Mutex::new(Manager::load()), stopping: AtomicBool::new(false) });
    {
        let server = server.clone();
        thread::spawn(move || server.watch());
    }
    server.listen();
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // the counters that the test sets, and the address the service gives
    #[derive(Default)]
    struct Script {
        rx: u64,
        tx: u64,
        endpoint: Option<SocketAddr>,
        refuse: bool,
    }

    struct ScriptedTunnel(Arc<Mutex<Script>>, conf::Key);

    impl Tunnel for ScriptedTunnel {
        fn peers(&self) -> Vec<PeerStats> {
            let script = self.0.lock().unwrap();
            vec![PeerStats {
                public_key: self.1,
                endpoint: script.endpoint,
                tx_bytes: script.tx,
                rx_bytes: script.rx,
                last_handshake: 0,
            }]
        }

        fn mtu(&self) -> u32 {
            1420
        }

        fn set_endpoint(&mut self, public_key: &conf::Key, address: SocketAddr) -> Result<(), String> {
            let mut script = self.0.lock().unwrap();
            assert_eq!(*public_key, self.1);
            if script.refuse {
                return Err("can't change the address of the server: refused".into());
            }
            script.endpoint = Some(address);
            Ok(())
        }
    }

    const CONFIG: &str = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.103.1.2\n\
                          [Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.103.1.0/24\n\
                          Endpoint = 192.0.2.1:51820\n# Fallback = 192.0.2.2:51820\nPersistentKeepalive = 25\n";

    // Office, on, as up() leaves it
    fn office() -> (Manager, Arc<Mutex<Script>>) {
        let config = conf::parse(CONFIG).unwrap();
        let failovers = resolve("Office", &config).unwrap();
        let endpoint = failovers[0].as_ref().map(Failover::address);
        let script = Arc::new(Mutex::new(Script { endpoint, ..Script::default() }));
        let tunnel = ScriptedTunnel(script.clone(), config.peers[0].public_key);
        let mut entry = Entry::new("Office".into(), GUID::from_u128(0), config);
        entry.active = Some(Active { tunnel: Box::new(tunnel), since: unix_now(), session: 1, id: next_id(), failovers });
        let manager = Manager {
            entries: vec![entry],
            #[cfg(not(feature = "testing"))]
            wireguard: None,
        };
        (manager, script)
    }

    // the counters at this second, then the watch
    fn poll(manager: &mut Manager, script: &Mutex<Script>, start: Instant, second: u64, rx: u64, tx: u64) -> Vec<Switch> {
        {
            let mut script = script.lock().unwrap();
            script.rx = rx;
            script.tx = tx;
        }
        manager.watch(start + Duration::from_secs(second))
    }

    // the address stops answering, rx stays: the handshakes of WireGuard go unanswered until the switch
    fn silent_until_switch(manager: &mut Manager, script: &Mutex<Script>, start: Instant, from: u64) -> (u64, Switch) {
        let rx = script.lock().unwrap().rx;
        for second in from..from + 60 {
            let mut switches = poll(manager, script, start, second, rx, 148 * second);
            if !switches.is_empty() {
                assert_eq!(switches.len(), 1);
                return (second, switches.remove(0));
            }
        }
        panic!("no switch");
    }

    #[test]
    fn a_line_goes_down() {
        let (mut manager, script) = office();
        let start = Instant::now();
        let info = &manager.list()[0];
        assert_eq!((info.endpoint.as_str(), info.peers[0].in_use.as_str()), ("192.0.2.1:51820", "192.0.2.1:51820"));
        assert_eq!(info.peers[0].fallbacks, ["192.0.2.2:51820"]);

        // it answers at first
        assert!(poll(&mut manager, &script, start, 0, 92, 148).is_empty());
        // the first handshake unanswered at 2, the switch 20 seconds later
        let (second, switch) = silent_until_switch(&mut manager, &script, start, 1);
        assert_eq!(second, 22);
        assert_eq!((switch.tunnel.as_str(), switch.peer), ("Office", 0));
        assert_eq!(switch.next.endpoint.to_string(), "192.0.2.2:51820");
        let address = failover::lookup(&switch.next.endpoint, failover::LOOKUP_TIME);
        manager.switch(switch, address);
        assert_eq!(script.lock().unwrap().endpoint, Some("192.0.2.2:51820".parse().unwrap()));
        let info = &manager.list()[0];
        assert_eq!((info.endpoint.as_str(), info.peers[0].in_use.as_str()), ("192.0.2.2:51820", "192.0.2.2:51820"));
        let peer = &info.peers[0];
        assert_eq!((peer.endpoint.as_str(), peer.address.as_str()), ("192.0.2.1:51820", "192.0.2.2:51820"));

        // the second line answers: it stays
        for second in 23..200 {
            assert!(poll(&mut manager, &script, start, second, 92 * second, 148 * second).is_empty(), "{}", second);
        }
        assert_eq!(manager.list()[0].peers[0].in_use, "192.0.2.2:51820");

        // it stops too: back to the first
        let (_, switch) = silent_until_switch(&mut manager, &script, start, 200);
        assert_eq!(switch.next.endpoint.to_string(), "192.0.2.1:51820");
        assert_eq!(switch.next.known, Some("192.0.2.1:51820".parse().unwrap()));
    }

    #[test]
    fn a_switch_that_doesnt_apply() {
        let (mut manager, script) = office();
        let start = Instant::now();
        assert!(poll(&mut manager, &script, start, 0, 92, 0).is_empty());
        let (_, switch) = silent_until_switch(&mut manager, &script, start, 1);
        let address = switch.next.known;
        // the tunnel went off and on during the lookup: the new connection starts again from the Endpoint
        manager.entries[0].active.as_mut().unwrap().id = next_id();
        manager.switch(switch, address);
        assert_eq!(script.lock().unwrap().endpoint, Some("192.0.2.1:51820".parse().unwrap()));
        // the driver refuses: the address stays, and the next try comes after another SILENCE
        script.lock().unwrap().refuse = true;
        let (second, switch) = silent_until_switch(&mut manager, &script, start, 100);
        manager.switch(switch, address);
        assert_eq!(manager.list()[0].peers[0].in_use, "192.0.2.1:51820");
        let (next, _) = silent_until_switch(&mut manager, &script, start, second + 1);
        assert_eq!(next, second + 1 + failover::SILENCE.as_secs());
        // off: nothing to watch
        manager.down("Office");
        assert!(poll(&mut manager, &script, start, 300, 0, 0).is_empty());
    }
}
