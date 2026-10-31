// The tunnels of the service, the same on every system: their configurations, the ones that are on and the
// fallbacks of their servers. Each system turns the tunnels on with its Engine, and talks with the app its own way.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Instant;

use crate::api::Page;
use crate::conf::{self, Config, IpNet};
use crate::failover::{self, Failover, Next, Poll};
use crate::ipc::{self, PeerInfo, Request, Response, TunnelInfo};
use crate::log;
use crate::store;
use crate::time::unix_now;
use crate::{device, devkey};

// What the tunnel says of a server
pub struct PeerStats {
    pub public_key: conf::Key,
    pub endpoint: Option<SocketAddr>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    // seconds since 1970, 0 when never
    pub last_handshake: u64,
}

pub trait Tunnel: Send {
    // the counters of each server, as the tunnel has them
    fn peers(&self) -> Vec<PeerStats>;
    fn mtu(&self) -> u32;
    // the index of its network interface
    fn interface(&self) -> u32;
    // another address for a server, a fallback
    fn set_endpoint(&mut self, public_key: &conf::Key, address: SocketAddr) -> Result<(), String>;
    // the routes and the DNS servers of Steps::after on, or off again
    fn after_login(&mut self, _on: bool) -> Result<(), String> {
        Ok(())
    }
    // now and then, while it's on: what the system doesn't keep by itself, after a change of network
    fn upkeep(&mut self) {}
}

// How the system turns a tunnel on, with the address of each server: None for one without Endpoint, and the routes
// of Steps::before. The tunnel goes off when it's dropped.
pub trait Engine: Send {
    fn start(
        &mut self,
        name: &str,
        id: &store::Id,
        config: &Config,
        endpoints: &[Option<SocketAddr>],
        steps: &Steps,
    ) -> Result<Box<dyn Tunnel>, String>;
}

// The routes of a tunnel, in two steps when its server requires a login. Before the login: its private networks and
// the login page, without the DNS servers, which would answer only for the login page; the internet goes on through
// the network of the computer, as without the VPN. With the login: the routes to the internet and the DNS servers.
// A tunnel without a login has all of them at once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Steps {
    pub before: Vec<IpNet>,
    pub after: Vec<IpNet>,
    // the DNS servers wait for the login
    pub dns_after: bool,
}

pub fn steps(config: &Config) -> Steps {
    let routes = config.routes();
    let page = config.login.as_deref().and_then(Page::parse).filter(|page| config.routes_to(page.host.into()));
    let Some(page) = page else {
        return Steps { before: routes, after: Vec::new(), dns_after: false };
    };
    let (mut before, after): (Vec<IpNet>, Vec<IpNet>) = routes.into_iter().partition(IpNet::is_private);
    if !before.iter().any(|net| net.contains(page.host.into())) {
        before.push(IpNet { addr: page.host.into(), prefix: 32 });
    }
    Steps { before, after, dns_after: true }
}

struct Active {
    tunnel: Box<dyn Tunnel>,
    since: u64,
    // of the user who turned it on: the Windows session, the user ID on macOS
    session: u32,
    // of this connection: a change of address asked for an earlier one doesn't apply
    id: u64,
    // for each server of the configuration, None for one without Endpoint
    failovers: Vec<Option<Failover>>,
    // the routes and the DNS servers of after the login are on
    logged_in: bool,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

// A change of address that the watch asks for, made out of the lock of the manager: a lookup can take seconds
pub struct Switch {
    tunnel: String,
    id: u64,
    peer: usize,
    pub next: Next,
}

struct Entry {
    name: String,
    id: store::Id,
    config: Config,
    // of the private key, for the details
    public_key: String,
    active: Option<Active>,
}

impl Entry {
    fn new(name: String, id: store::Id, config: Config) -> Entry {
        let public_key = conf::encode_key(&crate::x25519::public_key(&config.private_key));
        Entry { name, id, config, public_key, active: None }
    }
}

pub struct Manager {
    entries: Vec<Entry>,
    engine: Box<dyn Engine>,
}

// Who asks
pub struct Client {
    pub session: u32,
    pub can_manage: bool,
}

impl Manager {
    pub fn load(engine: Box<dyn Engine>) -> Manager {
        let mut entries = Vec::new();
        for stored in store::list() {
            match conf::parse(&stored.text) {
                Ok(config) => entries.push(Entry::new(stored.name, stored.id, config)),
                Err(error) => log!("{}: the configuration isn't valid anymore: {}", stored.name, error),
            }
        }
        log!("{} tunnels", entries.len());
        Manager { entries, engine }
    }

    fn find(&mut self, name: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|entry| entry.name.eq_ignore_ascii_case(name))
    }

    fn list(&self) -> Vec<TunnelInfo> {
        self.entries.iter().map(info).collect()
    }

    fn up(&mut self, name: &str, session: u32) -> Response {
        let Some(index) = self.entries.iter().position(|entry| entry.name.eq_ignore_ascii_case(name)) else {
            return Response::failure(ipc::NOT_FOUND, format!("There's no VPN named {}.", name));
        };
        let entry = &mut self.entries[index];
        if entry.active.is_some() {
            return Response::success();
        }
        let steps = steps(&entry.config);
        let started = resolve(&entry.name, &entry.config).and_then(|failovers| {
            let endpoints: Vec<Option<SocketAddr>> =
                failovers.iter().map(|failover| failover.as_ref().map(Failover::address)).collect();
            let tunnel = self.engine.start(&entry.name, &entry.id, &entry.config, &endpoints, &steps)?;
            Ok((tunnel, failovers))
        });
        match started {
            Ok((tunnel, failovers)) => {
                log!("{}: on, for the session {}", entry.name, session);
                if steps.dns_after {
                    log!("{}: the routes to the internet and the DNS servers wait for the login", entry.name);
                }
                let id = next_id();
                entry.active = Some(Active { tunnel, since: unix_now(), session, id, failovers, logged_in: false });
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
                self.entries.push(Entry::new(stored.name, stored.id, config));
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
                devkey::delete(&entry.name, &entry.id);
                log!("{}: removed", entry.name);
                Response::success()
            }
            Err(error) => Response::failure(ipc::FAILED, format!("Can't remove the configuration: {}.", error)),
        }
    }

    // only while it's off: the app knows the tunnels that are on by their names
    fn rename(&mut self, name: &str, new_name: &str) -> Response {
        if !conf::is_valid_name(new_name) {
            return Response::failure(ipc::INVALID, format!("\"{}\" can't be the name of a VPN.", new_name));
        }
        let Some(index) = self.entries.iter().position(|entry| entry.name.eq_ignore_ascii_case(name)) else {
            return Response::failure(ipc::NOT_FOUND, format!("There's no VPN named {}.", name));
        };
        let taken = self.entries.iter().enumerate().any(|(other, entry)| other != index && entry.name.eq_ignore_ascii_case(new_name));
        if taken {
            return Response::failure(ipc::EXISTS, format!("There's already a VPN named {}.", new_name));
        }
        let entry = &mut self.entries[index];
        if entry.name == new_name {
            return Response::success();
        }
        if entry.active.is_some() {
            return Response::failure(ipc::INVALID, format!("Disconnect {} before renaming it.", entry.name));
        }
        if let Err(error) = store::rename(&entry.name, new_name) {
            log!("{}: can't rename: {}", entry.name, error);
            return Response::failure(ipc::FAILED, format!("Can't rename the configuration: {}.", error));
        }
        devkey::rename(&entry.name, new_name, &entry.id);
        log!("{}: renamed {}", entry.name, new_name);
        entry.name = new_name.to_string();
        self.entries.sort_by_key(|entry| entry.name.to_lowercase());
        Response::success()
    }

    // The app logged in to the login page of the tunnel, or saw the session end: the routes and the DNS servers that
    // wait for the login go on, or off again. Nothing waits in a tunnel without a login.
    fn logged_in(&mut self, name: &str, logged_in: bool) -> Response {
        let Some(entry) = self.find(name) else {
            return Response::failure(ipc::NOT_FOUND, format!("There's no VPN named {}.", name));
        };
        let Some(active) = entry.active.as_mut() else {
            return Response::failure(ipc::INVALID, format!("{} isn't connected.", entry.name));
        };
        if active.logged_in == logged_in || !steps(&entry.config).dns_after {
            return Response::success();
        }
        match active.tunnel.after_login(logged_in) {
            Ok(()) => {
                active.logged_in = logged_in;
                if logged_in {
                    log!("{}: logged in, the routes to the internet and the DNS servers are on", entry.name);
                } else {
                    log!("{}: not logged in, the routes to the internet and the DNS servers are off", entry.name);
                }
                Response::success()
            }
            Err(error) => {
                log!("{}: {}", entry.name, error);
                Response::failure(ipc::FAILED, error)
            }
        }
    }

    // the user signed out
    pub fn session_ended(&mut self, session: u32, reason: &str) {
        for entry in &mut self.entries {
            if entry.active.as_ref().is_some_and(|active| active.session == session) {
                log!("{}: off, {}", entry.name, reason);
                entry.active = None;
            }
        }
    }

    // the sessions of the tunnels that are on
    pub fn sessions(&self) -> Vec<u32> {
        let mut sessions: Vec<u32> =
            self.entries.iter().filter_map(|entry| entry.active.as_ref().map(|active| active.session)).collect();
        sessions.sort_unstable();
        sessions.dedup();
        sessions
    }

    pub fn upkeep(&mut self) {
        for active in self.entries.iter_mut().filter_map(|entry| entry.active.as_mut()) {
            active.tunnel.upkeep();
        }
    }

    pub fn stop(&mut self) {
        for entry in &mut self.entries {
            if entry.active.take().is_some() {
                log!("{}: off, the service stops", entry.name);
            }
        }
    }

    // every POLL: whether the servers of the tunnels that are on still answer
    pub fn watch(&mut self, now: Instant) -> Vec<Switch> {
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
    pub fn switch(&mut self, switch: Switch, address: Option<SocketAddr>) {
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

    pub fn handle(&mut self, request: Request, client: &Client) -> Response {
        let denied = || {
            Response::failure(ipc::ACCESS_DENIED, "Only an administrator can add, rename or remove a VPN on this computer.")
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
            Request::Rename { name, new_name } => {
                if !client.can_manage {
                    return denied();
                }
                self.rename(&name, &new_name)
            }
            Request::LoggedIn { name, logged_in } => self.logged_in(&name, logged_in),
            Request::Sign { name, host, challenge, username, machine_id } => {
                self.sign(&name, host, &challenge, &username, machine_id)
            }
            Request::DeviceKey { name } => self.device_key(&name),
        }
    }

    // the ID of the device key of a tunnel: whose it is, not the key
    fn device_key(&mut self, name: &str) -> Response {
        let Some(entry) = self.find(name) else {
            return Response::failure(ipc::NOT_FOUND, format!("There's no VPN named {}.", name));
        };
        match device::key_id(&entry.name, &entry.id) {
            Ok(id) => Response { ok: true, device_key: Some(id), ..Response::default() },
            Err(error) => {
                log!("{}: can't read the device key: {}", entry.name, error);
                Response::failure(ipc::FAILED, format!("This computer can't read its device key: {}.", error))
            }
        }
    }

    // the device proof of a login, for a tunnel that's on
    fn sign(&mut self, name: &str, host: Ipv4Addr, challenge: &str, username: &str, machine_id: bool) -> Response {
        let Some(entry) = self.find(name) else {
            return Response::failure(ipc::NOT_FOUND, format!("There's no VPN named {}.", name));
        };
        if entry.active.is_none() {
            return Response::failure(ipc::INVALID, format!("{} isn't connected.", entry.name));
        }
        match device::prove(&entry.name, &entry.id, &entry.config, host, challenge, username, machine_id) {
            Ok(proof) => Response { ok: true, device: Some(proof), ..Response::default() },
            Err(error) => {
                log!("{}: can't sign the login: {}", entry.name, error);
                Response::failure(ipc::FAILED, format!("This computer can't sign the login: {}.", error))
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
                handshake: now.map_or(0, |now| now.last_handshake),
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
        after_login: steps(config).after.iter().map(ToString::to_string).collect(),
        logged_in: active.is_some_and(|active| active.logged_in),
        interface: active.map_or(0, |active| active.tunnel.interface()),
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

// The fallbacks of the servers that stop answering, until the service stops; `each` runs every POLL too, with the
// manager, for what the system has to look after
pub fn watch_loop(manager: &Mutex<Manager>, stopping: &AtomicBool, mut each: impl FnMut(&mut Manager, Instant)) {
    while !stopping.load(Ordering::SeqCst) {
        thread::sleep(failover::POLL);
        let now = Instant::now();
        let switches = {
            let mut manager = manager.lock().unwrap_or_else(|error| error.into_inner());
            each(&mut manager, now);
            manager.watch(now)
        };
        for switch in switches {
            // out of the lock, the app gets its answers meanwhile; the last address when it can't be found
            let address = failover::lookup(&switch.next.endpoint, failover::LOOKUP_TIME).or(switch.next.known);
            manager.lock().unwrap_or_else(|error| error.into_inner()).switch(switch, address);
        }
    }
}

// The tests: no tunnel. Each server sends a handshake and answers every second, from one second after the start,
// at any address but the port DEAD_PORT, where only this computer sends. The network interface of the tunnel is
// the loopback, where the login page of the tests is.
#[cfg(feature = "testing")]
pub mod fake {
    use super::*;

    const DEAD_PORT: u16 = 9;

    struct FakePeer {
        key: conf::Key,
        endpoint: Option<SocketAddr>,
        rx: u64,
        tx: u64,
        handshake: u64,
        // seconds since 1970, of the last count
        at: u64,
    }

    struct FakeTunnel {
        peers: Mutex<Vec<FakePeer>>,
        mtu: u32,
        interface: u32,
    }

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
                            peer.handshake = now;
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

        fn interface(&self) -> u32 {
            self.interface
        }

        fn set_endpoint(&mut self, public_key: &conf::Key, address: SocketAddr) -> Result<(), String> {
            let peers = self.peers.get_mut().unwrap_or_else(|error| error.into_inner());
            let peer = peers.iter_mut().find(|peer| peer.key == *public_key).ok_or("no such server")?;
            peer.endpoint = Some(address);
            Ok(())
        }
    }

    pub struct FakeEngine;

    impl Engine for FakeEngine {
        fn start(
            &mut self,
            _name: &str,
            _id: &store::Id,
            config: &Config,
            endpoints: &[Option<SocketAddr>],
            _steps: &Steps,
        ) -> Result<Box<dyn Tunnel>, String> {
            let now = unix_now();
            let peers = config
                .peers
                .iter()
                .zip(endpoints)
                .map(|(peer, endpoint)| FakePeer { key: peer.public_key, endpoint: *endpoint, rx: 0, tx: 0, handshake: 0, at: now })
                .collect();
            Ok(Box::new(FakeTunnel {
                peers: Mutex::new(peers),
                mtu: config.mtu.map_or(crate::net::DEFAULT_MTU, u32::from),
                interface: crate::net::loopback_interface().unwrap_or(0),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    // the counters that the test sets, and the address the service gives
    #[derive(Default)]
    struct Script {
        rx: u64,
        tx: u64,
        endpoint: Option<SocketAddr>,
        refuse: bool,
        // the routes of after the login, as the manager asked
        after_login: bool,
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

        fn interface(&self) -> u32 {
            7
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

        fn after_login(&mut self, on: bool) -> Result<(), String> {
            let mut script = self.0.lock().unwrap();
            if script.refuse {
                return Err("can't add the route to 0.0.0.0/0: refused".into());
            }
            script.after_login = on;
            Ok(())
        }
    }

    // turns nothing on: the tests make the tunnels themselves
    struct NoEngine;

    impl Engine for NoEngine {
        fn start(
            &mut self,
            _: &str,
            _: &store::Id,
            _: &Config,
            _: &[Option<SocketAddr>],
            _: &Steps,
        ) -> Result<Box<dyn Tunnel>, String> {
            Err("no engine in the tests".into())
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
        // a GUID on Windows, nothing on macOS
        #[allow(clippy::default_constructed_unit_structs)]
        let mut entry = Entry::new("Office".into(), store::Id::default(), config);
        let tunnel: Box<dyn Tunnel> = Box::new(tunnel);
        entry.active = Some(Active { tunnel, since: unix_now(), session: 1, id: next_id(), failovers, logged_in: false });
        let manager = Manager { entries: vec![entry], engine: Box::new(NoEngine) };
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
        // the tunnel refuses: the address stays, and the next try comes after another SILENCE
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

    #[test]
    fn renames_refused() {
        let (mut manager, _) = office();
        let config = conf::parse(CONFIG).unwrap();
        #[allow(clippy::default_constructed_unit_structs)]
        manager.entries.push(Entry::new("Home".into(), store::Id::default(), config));
        let admin = Client { session: 1, can_manage: true };
        let rename = |manager: &mut Manager, name: &str, new_name: &str, client: &Client| {
            manager.handle(Request::Rename { name: name.into(), new_name: new_name.into() }, client)
        };
        let user = Client { session: 1, can_manage: false };
        assert_eq!(rename(&mut manager, "Home", "Lab", &user).error_code(), ipc::ACCESS_DENIED);
        assert_eq!(rename(&mut manager, "Home", "../Lab", &admin).error_code(), ipc::INVALID);
        assert_eq!(rename(&mut manager, "Nowhere", "Lab", &admin).error_code(), ipc::NOT_FOUND);
        // another one has the name, whatever the case
        assert_eq!(rename(&mut manager, "Home", "office", &admin).error_code(), ipc::EXISTS);
        // on: the app knows it by its name
        assert_eq!(rename(&mut manager, "Office", "Work", &admin).error_code(), ipc::INVALID);
        // the same name: nothing to do
        assert!(rename(&mut manager, "home", "Home", &admin).ok);
        assert_eq!(manager.list().iter().map(|info| info.name.as_str()).collect::<Vec<_>>(), ["Office", "Home"]);
    }

    // CONFIG with a login page and other routes
    fn with_login(allowed_ips: &str) -> Config {
        let text = CONFIG
            .replace("[Interface]\n", "[Interface]\n# Login = http://10.103.1.1:8181/\n")
            .replace("AllowedIPs = 10.103.1.0/24", &format!("AllowedIPs = {}", allowed_ips));
        conf::parse(&text).unwrap()
    }

    #[test]
    fn two_steps_with_a_login() {
        let texts = |nets: &[IpNet]| nets.iter().map(ToString::to_string).collect::<Vec<_>>();
        // the full tunnel of the firewall: only the login page before the login
        let full = steps(&with_login("0.0.0.0/0, ::/0"));
        assert_eq!(texts(&full.before), ["10.103.1.1/32"]);
        assert_eq!(texts(&full.after), ["0.0.0.0/0", "::/0"]);
        assert!(full.dns_after);
        // a split tunnel: its routes as they are, only the DNS servers wait
        let split = steps(&with_login("192.168.1.0/24, 10.103.1.0/24"));
        assert_eq!(texts(&split.before), ["192.168.1.0/24", "10.103.1.0/24"]);
        assert!(split.after.is_empty() && split.dns_after);
        // a public network of the office waits with the internet
        let public = steps(&with_login("203.0.113.0/24, 10.103.1.0/24"));
        assert_eq!(texts(&public.before), ["10.103.1.0/24"]);
        assert_eq!(texts(&public.after), ["203.0.113.0/24"]);
        // no login, or a login page out of the tunnel: all at once
        let plain = steps(&conf::parse(&CONFIG.replace("10.103.1.0/24", "0.0.0.0/0")).unwrap());
        assert_eq!(texts(&plain.before), ["0.0.0.0/0"]);
        assert!(plain.after.is_empty() && !plain.dns_after);
        assert!(!steps(&with_login("192.168.1.0/24")).dns_after);
    }

    #[test]
    fn the_routes_of_after_the_login() {
        let (mut manager, script) = office();
        let user = Client { session: 1, can_manage: false };
        let logged_in = |manager: &mut Manager, on: bool| {
            manager.handle(Request::LoggedIn { name: "Office".into(), logged_in: on }, &user)
        };
        // no login page: nothing waits
        assert!(logged_in(&mut manager, true).ok);
        assert!(!script.lock().unwrap().after_login && !manager.list()[0].logged_in);
        assert!(manager.list()[0].after_login.is_empty());
        manager.entries[0].config = with_login("0.0.0.0/0");
        assert_eq!(manager.list()[0].after_login, ["0.0.0.0/0"]);
        assert!(logged_in(&mut manager, true).ok);
        assert!(script.lock().unwrap().after_login && manager.list()[0].logged_in);
        // the session ended
        assert!(logged_in(&mut manager, false).ok);
        assert!(!script.lock().unwrap().after_login && !manager.list()[0].logged_in);
        // refused by the system: still off, and said
        script.lock().unwrap().refuse = true;
        assert_eq!(logged_in(&mut manager, true).error_code(), ipc::FAILED);
        assert!(!manager.list()[0].logged_in);
        manager.down("Office");
        assert_eq!(logged_in(&mut manager, true).error_code(), ipc::INVALID);
    }

    #[test]
    fn sessions_of_the_tunnels_on() {
        let (mut manager, _) = office();
        assert_eq!(manager.sessions(), [1]);
        manager.session_ended(2, "another user signed out");
        assert_eq!(manager.sessions(), [1]);
        manager.session_ended(1, "the user signed out");
        assert!(manager.sessions().is_empty());
        assert!(!manager.list()[0].up);
    }
}
