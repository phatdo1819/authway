// The tunnels of the service, the same on every system: their configurations, the ones that are on and the
// fallbacks of their servers. Each system turns the tunnels on with its Engine, and talks with the app its own way.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::Instant;

use crate::api::Page;
use crate::conf::{self, Config, IpNet, OwnKeys};
use crate::failover::{self, Failover, Next, Poll};
use crate::ipc::{self, PeerInfo, Request, Response, TunnelInfo};
use crate::log;
use crate::store;
use crate::time::unix_now;
use crate::{device, x25519};

// seconds of packets sent without a handshake for a new private key: the server may take another one of the tunnel
const KEY_SILENCE: u64 = 30;
// the same for a key that worked: longer than WireGuard keeps a session, 180 seconds
const KEY_LOST: u64 = 200;
// a configuration replaced while the servers of the tunnel are looked up: they're looked up again, so many times
const UP_ATTEMPTS: usize = 3;

// The configurations and the device keys on disk. The tests keep them in memory, on the thread of each test, where
// a test can make the disk refuse
#[cfg(not(test))]
mod disk {
    pub use crate::devkey::{delete as delete_device_key, rename as rename_device_key};
    pub use crate::store::{delete, rename, save};
}

#[cfg(test)]
pub(crate) mod disk {
    use std::cell::RefCell;

    use crate::store::{Id, Stored};

    #[derive(Default)]
    pub struct Disk {
        // the name of each configuration, its first spelling, and its text
        pub files: Vec<(String, String)>,
        pub refuse: bool,
        // what was written, in order
        pub journal: Vec<String>,
    }

    thread_local! {
        pub static DISK: RefCell<Disk> = RefCell::new(Disk::default());
    }

    fn change(what: String, work: impl FnOnce(&mut Disk)) -> Result<(), String> {
        DISK.with(|disk| {
            let mut disk = disk.borrow_mut();
            if disk.refuse {
                return Err("the disk is full".to_string());
            }
            work(&mut disk);
            disk.journal.push(what);
            Ok(())
        })
    }

    // as the registry and the file system of macOS: a new case alone keeps the first spelling
    pub fn save(name: &str, text: &str) -> Result<Stored, String> {
        change(format!("save {}", name), |disk| {
            match disk.files.iter_mut().find(|(file, _)| file.eq_ignore_ascii_case(name)) {
                Some(file) => file.1 = text.to_string(),
                None => disk.files.push((name.to_string(), text.to_string())),
            }
        })?;
        #[allow(clippy::default_constructed_unit_structs)]
        Ok(Stored { name: name.to_string(), text: text.to_string(), id: Id::default() })
    }

    pub fn delete(name: &str) -> Result<(), String> {
        change(format!("delete {}", name), |disk| disk.files.retain(|(file, _)| !file.eq_ignore_ascii_case(name)))
    }

    pub fn rename(name: &str, new_name: &str) -> Result<(), String> {
        change(format!("rename {} {}", name, new_name), |disk| {
            if let Some(file) = disk.files.iter_mut().find(|(file, _)| file.eq_ignore_ascii_case(name)) {
                file.0 = new_name.to_string();
            }
        })
    }

    pub fn delete_device_key(tunnel: &str, _id: &Id) {
        DISK.with(|disk| disk.borrow_mut().journal.push(format!("delete the device key of {}", tunnel)));
    }

    pub fn rename_device_key(tunnel: &str, new_name: &str, _id: &Id) {
        DISK.with(|disk| disk.borrow_mut().journal.push(format!("rename the device key of {} {}", tunnel, new_name)));
    }
}

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
    // another private key for the tunnel, see conf::OwnKeys: the servers stay, the next packet makes a handshake
    fn set_private_key(&mut self, key: &conf::Key) -> Result<(), String>;
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
    key: KeyUse,
}

// The private key a tunnel that's on uses, and whether the server takes it: a handshake came after it was set
struct KeyUse {
    key: conf::Key,
    // seconds since 1970 when it was set, and the bytes sent then
    since: u64,
    tx: u64,
    confirmed: bool,
    // the latest handshake, and the bytes sent then
    handshake: u64,
    handshake_tx: u64,
}

impl KeyUse {
    fn new(key: conf::Key, since: u64, tx: u64) -> KeyUse {
        KeyUse { key, since, tx, confirmed: false, handshake: 0, handshake_tx: 0 }
    }
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
    // of this configuration: another one, imported in its place, has another
    revision: u64,
    // as in the configuration file
    config: Config,
    // the WireGuard keys this computer made for the server
    keys: OwnKeys,
    active: Option<Active>,
}

impl Entry {
    fn new(name: String, id: store::Id, config: Config, keys: OwnKeys) -> Entry {
        Entry { name, id, revision: next_id(), config, keys, active: None }
    }

    // another user of the computer turned it on: its login is theirs
    fn other_user(&self, client: &Client) -> bool {
        self.active.as_ref().is_some_and(|active| active.session != client.session)
    }

    // The tunnel is on with the key of its configuration file, and the server takes it: a handshake came with it.
    // Then the server has no other key of the tunnel, those of this computer are of before. Without keys of this
    // computer, the key of the file is the only one there is. The handshake is read here, not only at the watch of
    // every second: the app asks right after the login.
    fn on_file_key(&self) -> bool {
        let Some(active) = &self.active else { return false };
        if active.key.key != self.config.private_key {
            return false;
        }
        if self.keys.is_empty() || active.key.confirmed {
            return true;
        }
        let handshake = active.tunnel.peers().iter().map(|stats| stats.last_handshake).max().unwrap_or(0);
        handshake != 0 && handshake >= active.key.since
    }

    // the private key of the next connection: the one the server takes
    fn first_key(&self) -> conf::Key {
        self.keys.own.unwrap_or(self.config.private_key)
    }

    fn key_in_use(&self) -> conf::Key {
        self.active.as_ref().map_or_else(|| self.first_key(), |active| active.key.key)
    }

    // the keys to try, in this order, when the one in use gets no handshake
    fn candidates(&self) -> Vec<conf::Key> {
        let mut keys: Vec<conf::Key> = Vec::new();
        for key in [self.keys.own, Some(self.config.private_key), self.keys.pending].into_iter().flatten() {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        keys
    }

    fn describe(&self, key: &conf::Key) -> &'static str {
        if *key == self.config.private_key {
            "the key of the configuration file"
        } else if Some(*key) == self.keys.own {
            "the key of this computer"
        } else {
            "another key of this computer"
        }
    }

    fn save_keys(&self) -> Result<(), String> {
        // the tests never write the keys of the tunnels of this computer
        if cfg!(test) {
            return Ok(());
        }
        store::save_keys(&self.name, &self.keys).map_err(|error| {
            log!("{}: can't save the keys of this computer: {}", self.name, error);
            error
        })
    }

    // A handshake came with the key in use: the server takes it. The only proof of it: what the app says the server
    // said is only a hint, see Manager::wireguard_key. A new key becomes the one of this computer, and the one it
    // replaces stays as pending: the server may take it again, and a handshake in the second the key changed can
    // still be the one of the key before. The key of the file again means a new enrollment on the server, the key of
    // this computer is kept as pending too, in case the server only lost it for some time. A pending key stays: it's
    // the one being given to the server, or one it may take later. So a key the server may have is never forgotten,
    // only replaced as pending by a new key, which the server takes in place of the key of the file: see
    // Entry::on_file_key.
    fn confirmed(&mut self, key: conf::Key) {
        let before = self.keys;
        if Some(key) == self.keys.pending && Some(key) != self.keys.own {
            self.keys = OwnKeys { own: Some(key), pending: self.keys.own };
            log!("{}: the server takes the key of this computer, the configuration file no longer connects", self.name);
        } else if key == self.config.private_key && self.keys.own.is_some() {
            self.keys = OwnKeys { own: None, pending: self.keys.own };
            log!("{}: the server takes the key of the configuration file again", self.name);
        }
        if self.keys != before {
            let _ = self.save_keys();
        }
    }

    // While it's on: no handshake with the key in use, after packets were sent, for KEY_SILENCE seconds, or
    // KEY_LOST for a key that worked: the next key. The server may take another key of the tunnel: the key of the
    // file after a new enrollment, or the new key of this computer when its answer was lost.
    fn watch_key(&mut self, stats: &[PeerStats], now: u64) {
        let handshake = stats.iter().map(|stats| stats.last_handshake).max().unwrap_or(0);
        let tx: u64 = stats.iter().map(|stats| stats.tx_bytes).sum();
        let Some(active) = self.active.as_mut() else { return };
        let key = &mut active.key;
        if handshake > key.handshake {
            key.handshake = handshake;
            key.handshake_tx = tx;
        }
        // in seconds: on a fast network the handshake comes in the second the key was set, and the next one only 2
        // minutes later. A key is set after the latest handshake of the one before, so the same second is this key
        if !key.confirmed && handshake != 0 && handshake >= key.since {
            key.confirmed = true;
            let confirmed = key.key;
            self.confirmed(confirmed);
            return;
        }
        let quiet = if key.confirmed {
            now.saturating_sub(key.handshake) >= KEY_LOST && tx > key.handshake_tx
        } else {
            now.saturating_sub(key.since) >= KEY_SILENCE && tx > key.tx
        };
        if quiet {
            self.next_key(now, tx);
        }
    }

    fn next_key(&mut self, now: u64, tx: u64) {
        let candidates = self.candidates();
        let Some(active) = self.active.as_mut() else { return };
        let position = candidates.iter().position(|key| *key == active.key.key).map_or(0, |position| position + 1);
        let next = candidates[position % candidates.len()];
        match active.tunnel.set_private_key(&next) {
            Ok(()) => {
                active.key = KeyUse::new(next, now, tx);
                log!("{}: no handshake, now with {}", self.name, self.describe(&next));
            }
            Err(error) => {
                // again after another silence
                active.key.since = now;
                active.key.tx = tx;
                active.key.handshake_tx = tx;
                log!("{}: {}", self.name, error);
            }
        }
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

// Turning a tunnel on, in three steps: what it needs, under the lock of the manager; the addresses of its servers,
// out of it, since a lookup can take seconds and the apps of every user wait for the lock; then on, under the lock
// again, unless its configuration changed meanwhile. See handle.
enum UpStep {
    Done(Response),
    Find(UpPlan),
}

struct UpPlan {
    name: String,
    revision: u64,
    config: Config,
}

fn not_found(name: &str) -> Response {
    Response::failure(ipc::NOT_FOUND, format!("There's no VPN named {}.", name))
}

fn in_use(name: &str) -> Response {
    Response::failure(ipc::IN_USE, format!("{} is connected by another user of this computer.", name))
}

fn others_login(name: &str) -> Response {
    Response::failure(ipc::ACCESS_DENIED, format!("{} was connected by another user of this computer.", name))
}

impl Manager {
    pub fn load(engine: Box<dyn Engine>) -> Manager {
        let mut entries = Vec::new();
        for stored in store::list() {
            match conf::parse(&stored.text) {
                Ok(config) => {
                    let keys = store::load_keys(&stored.name);
                    entries.push(Entry::new(stored.name, stored.id, config, keys))
                }
                Err(error) => log!("{}: the configuration isn't valid anymore: {}", stored.name, error),
            }
        }
        log!("{} tunnels", entries.len());
        Manager { entries, engine }
    }

    fn find(&mut self, name: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|entry| entry.name.eq_ignore_ascii_case(name))
    }

    fn index_of(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|entry| entry.name.eq_ignore_ascii_case(name))
    }

    // as the user of the session sees them
    fn list(&self, session: u32) -> Vec<TunnelInfo> {
        self.entries.iter().map(|entry| info(entry, session)).collect()
    }

    // The login of a tunnel is the one of the user who turned it on: another user can't act on it, an
    // administrator neither. None when the client may.
    fn others(&self, name: &str, client: &Client) -> Option<Response> {
        let entry = self.entries.iter().find(|entry| entry.name.eq_ignore_ascii_case(name))?;
        entry.other_user(client).then(|| others_login(&entry.name))
    }

    // Whether the tunnel can go on for the client: not while it's on for another user, and not when it would turn
    // off a tunnel of another user, unless the client can manage the VPNs, and so remove them anyway
    fn can_go_on(&self, index: usize, client: &Client) -> Option<Response> {
        let entry = &self.entries[index];
        if entry.other_user(client) {
            return Some(in_use(&entry.name));
        }
        if entry.active.is_some() {
            return Some(Response::success());
        }
        if client.can_manage {
            return None;
        }
        self.entries.iter().find(|other| other.other_user(client)).map(|other| in_use(&other.name))
    }

    fn plan_up(&self, name: &str, client: &Client) -> UpStep {
        let Some(index) = self.index_of(name) else {
            return UpStep::Done(not_found(name));
        };
        if let Some(response) = self.can_go_on(index, client) {
            return UpStep::Done(response);
        }
        let entry = &self.entries[index];
        UpStep::Find(UpPlan { name: entry.name.clone(), revision: entry.revision, config: entry.config.clone() })
    }

    // with the servers found out of the lock: None when the configuration changed meanwhile, to find them again
    fn finish_up(
        &mut self,
        plan: &UpPlan,
        client: &Client,
        found: Result<Vec<Option<Failover>>, String>,
    ) -> Option<Response> {
        let Some(index) = self.index_of(&plan.name) else {
            return Some(not_found(&plan.name));
        };
        if self.entries[index].revision != plan.revision {
            return None;
        }
        // another request turned it, or another one, on meanwhile
        if let Some(response) = self.can_go_on(index, client) {
            return Some(response);
        }
        Some(self.start(index, client.session, found))
    }

    // all under the lock: for the tests, the services go through handle()
    fn up(&mut self, name: &str, client: &Client) -> Response {
        match self.plan_up(name, client) {
            UpStep::Done(response) => response,
            UpStep::Find(plan) => {
                let found = resolve(&plan.name, &plan.config);
                self.finish_up(&plan, client, found).expect("the same configuration")
            }
        }
    }

    fn start(&mut self, index: usize, session: u32, found: Result<Vec<Option<Failover>>, String>) -> Response {
        // One VPN at a time: two tunnels would take the same routes, and one of them would carry nothing while it says
        // it's connected. The others go off first, with their routes and DNS servers, even if this one can't start.
        let name = self.entries[index].name.clone();
        for (other, entry) in self.entries.iter_mut().enumerate() {
            if other != index && entry.active.take().is_some() {
                log!("{}: off, {} goes on", entry.name, name);
            }
        }
        let entry = &mut self.entries[index];
        let steps = steps(&entry.config);
        let key = entry.first_key();
        let mut config = entry.config.clone();
        config.private_key = key;
        let started = found.and_then(|failovers| {
            let endpoints: Vec<Option<SocketAddr>> =
                failovers.iter().map(|failover| failover.as_ref().map(Failover::address)).collect();
            // before the start: the first handshake can come while the routes are set
            let since = unix_now();
            let tunnel = self.engine.start(&entry.name, &entry.id, &config, &endpoints, &steps)?;
            Ok((tunnel, failovers, since))
        });
        match started {
            Ok((tunnel, failovers, key_since)) => {
                log!("{}: on, for the session {}", entry.name, session);
                if steps.dns_after {
                    log!("{}: the routes to the internet and the DNS servers wait for the login", entry.name);
                }
                if key != entry.config.private_key {
                    log!("{}: with {}", entry.name, entry.describe(&key));
                }
                let id = next_id();
                let since = unix_now();
                let key = KeyUse::new(key, key_since, 0);
                entry.active = Some(Active { tunnel, since, session, id, failovers, logged_in: false, key });
                Response::success()
            }
            Err(error) => {
                log!("{}: can't turn on: {}", entry.name, error);
                Response::failure(ipc::FAILED, error)
            }
        }
    }

    // the VPN of another user: only for a user who can manage the VPNs, and so remove it anyway
    fn down(&mut self, name: &str, client: &Client) -> Response {
        if !client.can_manage {
            if let Some(refused) = self.others(name, client) {
                return refused;
            }
        }
        match self.find(name) {
            None => not_found(name),
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
        let existing = self.index_of(name);
        if existing.is_some() && !replace {
            return Response::failure(ipc::EXISTS, format!("There's already a VPN named {}.", name));
        }
        // On the disk first: the VPN stays as it was, on too, when it can't be saved. Another spelling of the name
        // is a rename first, with the GUID and the device key: the registry and the file system keep the first one.
        if let Some(index) = existing.filter(|&index| self.entries[index].name != name) {
            let entry = &mut self.entries[index];
            if let Err(error) = disk::rename(&entry.name, name) {
                log!("{}: can't rename: {}", entry.name, error);
                return Response::failure(ipc::FAILED, format!("Can't rename the configuration: {}.", error));
            }
            disk::rename_device_key(&entry.name, name, &entry.id);
            log!("{}: renamed {}", entry.name, name);
            entry.name = name.to_string();
        }
        let stored = match disk::save(name, text) {
            Ok(stored) => stored,
            Err(error) => {
                log!("{}: can't save: {}", name, error);
                return Response::failure(ipc::FAILED, format!("Can't save the configuration: {}.", error));
            }
        };
        if let Some(index) = existing {
            if self.entries.remove(index).active.is_some() {
                log!("{}: off, replaced", name);
            }
        }
        log!("{}: {}", name, if existing.is_some() { "replaced" } else { "added" });
        for ignored in &config.ignored {
            log!("{}: {} is ignored", name, ignored);
        }
        // the keys made for the old file are gone with it
        self.entries.push(Entry::new(stored.name, stored.id, config, OwnKeys::default()));
        self.entries.sort_by_key(|entry| entry.name.to_lowercase());
        Response::success()
    }

    fn remove(&mut self, name: &str) -> Response {
        let Some(index) = self.index_of(name) else {
            return not_found(name);
        };
        // from the disk first: the VPN stays as it was, on too, when it can't be removed
        if let Err(error) = disk::delete(&self.entries[index].name) {
            log!("{}: can't remove: {}", self.entries[index].name, error);
            return Response::failure(ipc::FAILED, format!("Can't remove the configuration: {}.", error));
        }
        // off, with its routes and DNS servers
        let entry = self.entries.remove(index);
        drop(entry.active);
        disk::delete_device_key(&entry.name, &entry.id);
        log!("{}: removed", entry.name);
        Response::success()
    }

    // only while it's off: the app knows the tunnels that are on by their names
    fn rename(&mut self, name: &str, new_name: &str) -> Response {
        if !conf::is_valid_name(new_name) {
            return Response::failure(ipc::INVALID, format!("\"{}\" can't be the name of a VPN.", new_name));
        }
        let Some(index) = self.index_of(name) else {
            return not_found(name);
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
        if let Err(error) = disk::rename(&entry.name, new_name) {
            log!("{}: can't rename: {}", entry.name, error);
            return Response::failure(ipc::FAILED, format!("Can't rename the configuration: {}.", error));
        }
        disk::rename_device_key(&entry.name, new_name, &entry.id);
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

    // every POLL: whether the servers of the tunnels that are on still answer, and still take their key
    pub fn watch(&mut self, now: Instant) -> Vec<Switch> {
        let unix = unix_now();
        let mut switches = Vec::new();
        for entry in &mut self.entries {
            let Some(active) = &entry.active else { continue };
            let keys = entry.candidates().len() > 1;
            if !keys && active.failovers.iter().all(Option::is_none) {
                continue;
            }
            let stats = active.tunnel.peers();
            if keys {
                entry.watch_key(&stats, unix);
            }
            let Some(active) = &mut entry.active else { continue };
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

    // Under the lock: the services go through handle(), which finds the servers of a tunnel that goes on out of it
    fn handle_locked(&mut self, request: Request, client: &Client) -> Response {
        let denied = || {
            Response::failure(ipc::ACCESS_DENIED, "Only an administrator can add, rename or remove a VPN on this computer.")
        };
        // the login of a tunnel, its routes and its keys: only the user who turned it on
        let session_name = match &request {
            Request::LoggedIn { name, .. }
            | Request::Sign { name, .. }
            | Request::DeviceKey { name }
            | Request::NewWireguardKey { name, .. }
            | Request::WireguardKey { name, .. } => Some(name),
            _ => None,
        };
        if let Some(refused) = session_name.and_then(|name| self.others(name, client)) {
            return refused;
        }
        match request {
            Request::List => {
                Response { ok: true, tunnels: self.list(client.session), can_manage: client.can_manage, ..Response::default() }
            }
            Request::Up { name } => self.up(&name, client),
            Request::Down { name } => self.down(&name, client),
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
            Request::NewWireguardKey { name, host, challenge } => self.new_wireguard_key(&name, host, &challenge),
            Request::WireguardKey { name, accepted } => self.wireguard_key(&name, accepted),
        }
    }

    // A WireGuard key for the server of a tunnel that's on, kept pending before the request leaves: if the answer of
    // the server is lost, the tunnel can still try the key when the one in use stops working. Only in place of the key
    // of the configuration file, which the server takes now: the server has no other key of the tunnel, so the
    // pending key this one replaces isn't one it has.
    fn new_wireguard_key(&mut self, name: &str, host: Ipv4Addr, challenge: &str) -> Response {
        let Some(entry) = self.find(name) else {
            return not_found(name);
        };
        if entry.active.is_none() {
            return Response::failure(ipc::INVALID, format!("{} isn't connected.", entry.name));
        }
        if !entry.on_file_key() {
            log!("{}: no key of this computer for the server: the tunnel doesn't use the key of the file", entry.name);
            return Response::failure(ipc::INVALID, format!("{} doesn't use the key of its configuration file.", entry.name));
        }
        let made = x25519::new_private_key().and_then(|key| {
            let request = device::wireguard_key(&entry.name, &entry.id, &entry.config, host, challenge, &x25519::public_key(&key))?;
            Ok((key, request))
        });
        let (key, request) = match made {
            Ok(made) => made,
            Err(error) => {
                log!("{}: can't make a key for the server: {}", entry.name, error);
                return Response::failure(ipc::FAILED, format!("This computer can't make its key: {}.", error));
            }
        };
        let before = entry.keys.pending;
        entry.keys.pending = Some(key);
        if let Err(error) = entry.save_keys() {
            entry.keys.pending = before;
            return Response::failure(ipc::FAILED, format!("This computer can't keep its key: {}.", error));
        }
        log!("{}: made a WireGuard key for the server", entry.name);
        Response { ok: true, new_key: Some(request), ..Response::default() }
    }

    // What the app says the server said of the pending key. Only a hint: any program of the user can say it, so the
    // keys stay as they are, and only a handshake makes the pending key the one of this computer (see
    // Entry::confirmed). Taken: the tunnel tries it at once, and goes back to the key of the file if no handshake
    // comes. Refused: forgotten. Both only while the tunnel works with the key of the file, as when the app asked for
    // the key: else the pending key may be one the server has.
    fn wireguard_key(&mut self, name: &str, accepted: bool) -> Response {
        let Some(entry) = self.find(name) else {
            return not_found(name);
        };
        let Some(key) = entry.keys.pending else {
            return Response::success();
        };
        if !entry.on_file_key() {
            log!("{}: what the server said of the key of this computer doesn't apply: the tunnel moved", entry.name);
            return Response::failure(ipc::INVALID, format!("{} doesn't use the key of its configuration file.", entry.name));
        }
        if !accepted {
            entry.keys.pending = None;
            log!("{}: the server refused the key of this computer", entry.name);
            let _ = entry.save_keys();
            return Response::success();
        }
        let active = entry.active.as_mut().expect("on");
        let tx = active.tunnel.peers().iter().map(|stats| stats.tx_bytes).sum();
        // before the change: the handshake it starts can come at once
        let since = unix_now();
        match active.tunnel.set_private_key(&key) {
            Ok(()) => {
                active.key = KeyUse::new(key, since, tx);
                log!("{}: the server says it takes the key of this computer, waiting for its handshake", entry.name);
                Response::success()
            }
            Err(error) => {
                log!("{}: {}", entry.name, error);
                Response::failure(ipc::FAILED, error)
            }
        }
    }

    // the ID of the device key of a tunnel: whose it is, not the key
    fn device_key(&mut self, name: &str) -> Response {
        let Some(entry) = self.find(name) else {
            return not_found(name);
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

// a tunnel as the user of the session sees it
fn info(entry: &Entry, session: u32) -> TunnelInfo {
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
        other_user: active.is_some_and(|active| active.session != session),
        interface: active.map_or(0, |active| active.tunnel.interface()),
        since: active.map_or(0, |active| active.since),
        handshake: peers.iter().map(|peer| peer.handshake).max().unwrap_or(0),
        rx_bytes: peers.iter().map(|peer| peer.rx_bytes).sum(),
        tx_bytes: peers.iter().map(|peer| peer.tx_bytes).sum(),
        // of the private key in use, or of the next connection
        public_key: conf::encode_key(&x25519::public_key(&entry.key_in_use())),
        own_key: entry.key_in_use() != config.private_key,
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
    let failovers = config
        .peers
        .iter()
        .map(|peer| Failover::start(peer, failover::CONNECT_LOOKUP_TIME))
        .collect::<Result<Vec<_>, _>>()?;
    for failover in failovers.iter().flatten().filter(|failover| failover.index() > 0) {
        log!("{}: the endpoint can't be found, fallback {} instead: {}", name, failover.index(), failover.endpoint());
    }
    Ok(failovers)
}

fn lock(manager: &Mutex<Manager>) -> MutexGuard<'_, Manager> {
    manager.lock().unwrap_or_else(|error| error.into_inner())
}

// A request of an app, for the service: under the lock of the manager, but the servers of a tunnel that goes on are
// looked up out of it, so the apps of every user get their answers meanwhile
pub fn handle(manager: &Mutex<Manager>, request: Request, client: &Client) -> Response {
    handle_with(manager, request, client, resolve)
}

fn handle_with(
    manager: &Mutex<Manager>,
    request: Request,
    client: &Client,
    find: impl Fn(&str, &Config) -> Result<Vec<Option<Failover>>, String>,
) -> Response {
    let Request::Up { name } = request else {
        return lock(manager).handle_locked(request, client);
    };
    for _ in 0..UP_ATTEMPTS {
        let step = lock(manager).plan_up(&name, client);
        let plan = match step {
            UpStep::Done(response) => return response,
            UpStep::Find(plan) => plan,
        };
        let found = find(&plan.name, &plan.config);
        let finished = lock(manager).finish_up(&plan, client, found);
        if let Some(response) = finished {
            return response;
        }
        log!("{}: replaced while its servers were looked up, again", plan.name);
    }
    Response::failure(ipc::FAILED, format!("The configuration of {} changed while it was turning on.", name))
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

        // the fake servers answer any key
        fn set_private_key(&mut self, _key: &conf::Key) -> Result<(), String> {
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
        // the private key the manager set, and the latest handshake
        key: Option<conf::Key>,
        handshake: u64,
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
                last_handshake: script.handshake,
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

        fn set_private_key(&mut self, key: &conf::Key) -> Result<(), String> {
            let mut script = self.0.lock().unwrap();
            if script.refuse {
                return Err("can't change the key of the tunnel: refused".into());
            }
            script.key = Some(*key);
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

    // the user who turned Office on, in office(); another one, who can or can't manage the VPNs
    const OWNER: Client = Client { session: 1, can_manage: false };
    const OTHER: Client = Client { session: 2, can_manage: false };
    const OTHER_ADMIN: Client = Client { session: 2, can_manage: true };

    // Office, on, as up() leaves it
    fn office() -> (Manager, Arc<Mutex<Script>>) {
        let config = conf::parse(CONFIG).unwrap();
        let failovers = resolve("Office", &config).unwrap();
        let endpoint = failovers[0].as_ref().map(Failover::address);
        let script = Arc::new(Mutex::new(Script { endpoint, ..Script::default() }));
        let tunnel = ScriptedTunnel(script.clone(), config.peers[0].public_key);
        let key = KeyUse::new(config.private_key, unix_now(), 0);
        // a GUID on Windows, nothing on macOS
        #[allow(clippy::default_constructed_unit_structs)]
        let mut entry = Entry::new("Office".into(), store::Id::default(), config, OwnKeys::default());
        let tunnel: Box<dyn Tunnel> = Box::new(tunnel);
        let since = unix_now();
        entry.active = Some(Active { tunnel, since, session: 1, id: next_id(), failovers, logged_in: false, key });
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

    // starts every tunnel, and keeps their names
    #[derive(Default)]
    struct StartEngine(Arc<Mutex<Vec<String>>>);

    impl Engine for StartEngine {
        fn start(
            &mut self,
            name: &str,
            _: &store::Id,
            config: &Config,
            endpoints: &[Option<SocketAddr>],
            _: &Steps,
        ) -> Result<Box<dyn Tunnel>, String> {
            self.0.lock().unwrap().push(name.to_string());
            let script = Arc::new(Mutex::new(Script { endpoint: endpoints[0], ..Script::default() }));
            Ok(Box::new(ScriptedTunnel(script, config.peers[0].public_key)))
        }
    }

    fn on(manager: &Manager) -> Vec<String> {
        manager.list(1).into_iter().filter(|info| info.up).map(|info| info.name).collect()
    }

    #[test]
    fn one_vpn_at_a_time() {
        let (mut manager, _) = office();
        #[allow(clippy::default_constructed_unit_structs)]
        let home = Entry::new("Home".into(), store::Id::default(), conf::parse(CONFIG).unwrap(), OwnKeys::default());
        manager.entries.push(home);
        let started = Arc::new(Mutex::new(Vec::new()));
        manager.engine = Box::new(StartEngine(started.clone()));
        assert_eq!(on(&manager), ["Office"]);
        // Home goes on: Office goes off
        assert!(manager.up("Home", &OWNER).ok);
        assert_eq!(on(&manager), ["Home"]);
        // again: nothing changes, nothing starts again
        assert!(manager.up("home", &OWNER).ok);
        assert_eq!(on(&manager), ["Home"]);
        assert_eq!(*started.lock().unwrap(), ["Home"]);
        // and back
        assert!(manager.up("Office", &OWNER).ok);
        assert_eq!(on(&manager), ["Office"]);
        // a VPN that doesn't exist turns nothing off
        assert!(!manager.up("Lab", &OWNER).ok);
        assert_eq!(on(&manager), ["Office"]);
        // one that can't start: the other is off anyway, as when it starts
        manager.engine = Box::new(NoEngine);
        assert!(!manager.up("Home", &OWNER).ok);
        assert!(on(&manager).is_empty());
    }

    #[test]
    fn a_line_goes_down() {
        let (mut manager, script) = office();
        let start = Instant::now();
        let info = &manager.list(1)[0];
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
        let info = &manager.list(1)[0];
        assert_eq!((info.endpoint.as_str(), info.peers[0].in_use.as_str()), ("192.0.2.2:51820", "192.0.2.2:51820"));
        let peer = &info.peers[0];
        assert_eq!((peer.endpoint.as_str(), peer.address.as_str()), ("192.0.2.1:51820", "192.0.2.2:51820"));

        // the second line answers: it stays
        for second in 23..200 {
            assert!(poll(&mut manager, &script, start, second, 92 * second, 148 * second).is_empty(), "{}", second);
        }
        assert_eq!(manager.list(1)[0].peers[0].in_use, "192.0.2.2:51820");

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
        assert_eq!(manager.list(1)[0].peers[0].in_use, "192.0.2.1:51820");
        let (next, _) = silent_until_switch(&mut manager, &script, start, second + 1);
        assert_eq!(next, second + 1 + failover::SILENCE.as_secs());
        // off: nothing to watch
        manager.down("Office", &OWNER);
        assert!(poll(&mut manager, &script, start, 300, 0, 0).is_empty());
    }

    #[test]
    fn renames_refused() {
        let (mut manager, _) = office();
        let config = conf::parse(CONFIG).unwrap();
        #[allow(clippy::default_constructed_unit_structs)]
        manager.entries.push(Entry::new("Home".into(), store::Id::default(), config, OwnKeys::default()));
        let admin = Client { session: 1, can_manage: true };
        let rename = |manager: &mut Manager, name: &str, new_name: &str, client: &Client| {
            manager.handle_locked(Request::Rename { name: name.into(), new_name: new_name.into() }, client)
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
        assert_eq!(manager.list(1).iter().map(|info| info.name.as_str()).collect::<Vec<_>>(), ["Office", "Home"]);
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
            manager.handle_locked(Request::LoggedIn { name: "Office".into(), logged_in: on }, &user)
        };
        // no login page: nothing waits
        assert!(logged_in(&mut manager, true).ok);
        assert!(!script.lock().unwrap().after_login && !manager.list(1)[0].logged_in);
        assert!(manager.list(1)[0].after_login.is_empty());
        manager.entries[0].config = with_login("0.0.0.0/0");
        assert_eq!(manager.list(1)[0].after_login, ["0.0.0.0/0"]);
        assert!(logged_in(&mut manager, true).ok);
        assert!(script.lock().unwrap().after_login && manager.list(1)[0].logged_in);
        // the session ended
        assert!(logged_in(&mut manager, false).ok);
        assert!(!script.lock().unwrap().after_login && !manager.list(1)[0].logged_in);
        // refused by the system: still off, and said
        script.lock().unwrap().refuse = true;
        assert_eq!(logged_in(&mut manager, true).error_code(), ipc::FAILED);
        assert!(!manager.list(1)[0].logged_in);
        manager.down("Office", &OWNER);
        assert_eq!(logged_in(&mut manager, true).error_code(), ipc::INVALID);
    }

    // Office with the keys of this computer, on with the first one since 1000, as up() leaves it
    fn office_with(keys: OwnKeys) -> (Manager, Arc<Mutex<Script>>) {
        let (mut manager, script) = office();
        let entry = &mut manager.entries[0];
        entry.keys = keys;
        let first = entry.first_key();
        entry.active.as_mut().unwrap().key = KeyUse::new(first, 1000, 0);
        (manager, script)
    }

    // the bytes sent and the latest handshake at this second, then the watch of the key
    fn watch_key(manager: &mut Manager, script: &Mutex<Script>, now: u64, tx: u64, handshake: u64) {
        {
            let mut script = script.lock().unwrap();
            script.tx = tx;
            script.handshake = handshake;
        }
        let stats = manager.entries[0].active.as_ref().unwrap().tunnel.peers();
        manager.entries[0].watch_key(&stats, now);
    }

    const NEW_KEY: conf::Key = [9; 32];

    #[test]
    fn a_new_key_the_server_takes() {
        let file = conf::parse(CONFIG).unwrap().private_key;
        // the answer of the server was lost: the key of the file stops working
        let (mut manager, script) = office_with(OwnKeys { own: None, pending: Some(NEW_KEY) });
        assert_eq!(manager.entries[0].candidates(), [file, NEW_KEY]);
        watch_key(&mut manager, &script, 1010, 148, 0);
        assert_eq!(script.lock().unwrap().key, None);
        // packets for KEY_SILENCE seconds and no handshake: the new key
        watch_key(&mut manager, &script, 1000 + KEY_SILENCE, 296, 0);
        assert_eq!(script.lock().unwrap().key, Some(NEW_KEY));
        // a handshake with it: the server took it, it's the key of this computer now
        watch_key(&mut manager, &script, 1031, 400, 1031);
        assert_eq!(manager.entries[0].keys, OwnKeys { own: Some(NEW_KEY), pending: None });
        let info = &manager.list(1)[0];
        assert!(info.own_key);
        assert_eq!(info.public_key, conf::encode_key(&x25519::public_key(&NEW_KEY)));
        // no packets: nothing to say, however long
        script.lock().unwrap().key = None;
        watch_key(&mut manager, &script, 1031 + KEY_LOST * 3, 400, 1031);
        assert_eq!(script.lock().unwrap().key, None);
        // the next connection starts with it
        assert_eq!(manager.entries[0].first_key(), NEW_KEY);
    }

    #[test]
    fn the_key_of_the_file_again() {
        let file = conf::parse(CONFIG).unwrap().private_key;
        let (mut manager, script) = office_with(OwnKeys { own: Some(NEW_KEY), pending: None });
        watch_key(&mut manager, &script, 1001, 148, 1001);
        assert_eq!(manager.entries[0].keys.own, Some(NEW_KEY));
        // the handshakes stop, while packets go: a new enrollment on the server
        watch_key(&mut manager, &script, 1100, 5000, 1001);
        assert_eq!(script.lock().unwrap().key, None);
        watch_key(&mut manager, &script, 1001 + KEY_LOST, 10000, 1001);
        assert_eq!(script.lock().unwrap().key, Some(file));
        watch_key(&mut manager, &script, 1204, 10100, 1203);
        // the key of this computer is kept a while, the next connection starts with the key of the file
        assert_eq!(manager.entries[0].keys, OwnKeys { own: None, pending: Some(NEW_KEY) });
        assert_eq!(manager.entries[0].first_key(), file);
        assert!(!manager.list(1)[0].own_key);
        // the key of the file works at once at the next connection: the pending key stays, it may be the one
        // being given to the server right now
        let (mut manager, script) = office_with(OwnKeys { own: None, pending: Some(NEW_KEY) });
        watch_key(&mut manager, &script, 1001, 148, 1001);
        assert_eq!(manager.entries[0].keys, OwnKeys { own: None, pending: Some(NEW_KEY) });
    }

    #[test]
    fn a_handshake_in_the_second_the_key_was_set() {
        // on a fast network: the server takes the key, and the next handshake comes only 2 minutes later
        let (mut manager, script) = office_with(OwnKeys { own: Some(NEW_KEY), pending: None });
        watch_key(&mut manager, &script, 1000, 148, 1000);
        watch_key(&mut manager, &script, 1000 + KEY_SILENCE, 5000, 1000);
        assert_eq!(script.lock().unwrap().key, None);
        // the same after a change of key
        let (mut manager, script) = office_with(OwnKeys { own: None, pending: Some(NEW_KEY) });
        watch_key(&mut manager, &script, 1000 + KEY_SILENCE, 296, 0);
        assert_eq!(script.lock().unwrap().key, Some(NEW_KEY));
        watch_key(&mut manager, &script, 1000 + KEY_SILENCE, 400, 1000 + KEY_SILENCE);
        assert_eq!(manager.entries[0].keys, OwnKeys { own: Some(NEW_KEY), pending: None });
        script.lock().unwrap().key = None;
        watch_key(&mut manager, &script, 1000 + 2 * KEY_SILENCE, 5000, 1000 + KEY_SILENCE);
        assert_eq!(script.lock().unwrap().key, None);
    }

    #[test]
    fn a_tunnel_that_refuses_the_key() {
        let (mut manager, script) = office_with(OwnKeys { own: None, pending: Some(NEW_KEY) });
        script.lock().unwrap().refuse = true;
        watch_key(&mut manager, &script, 1000 + KEY_SILENCE, 296, 0);
        assert_eq!(script.lock().unwrap().key, None);
        // again after another silence
        script.lock().unwrap().refuse = false;
        watch_key(&mut manager, &script, 1000 + KEY_SILENCE + 10, 400, 0);
        assert_eq!(script.lock().unwrap().key, None);
        watch_key(&mut manager, &script, 1000 + 2 * KEY_SILENCE, 500, 0);
        assert_eq!(script.lock().unwrap().key, Some(NEW_KEY));
    }

    const OLD_KEY: conf::Key = [7; 32];

    // what the app says the server said of the pending key
    fn answer(manager: &mut Manager, accepted: bool) -> Response {
        manager.handle_locked(Request::WireguardKey { name: "Office".into(), accepted }, &OWNER)
    }

    fn new_key_request() -> Request {
        Request::NewWireguardKey { name: "Office".into(), host: "10.103.1.1".parse().unwrap(), challenge: "C".into() }
    }

    #[test]
    fn what_the_server_said_of_the_key() {
        // asked for in place of the key of the file, which works: a handshake came with it
        let (mut manager, script) = office_with(OwnKeys { own: None, pending: Some(NEW_KEY) });
        script.lock().unwrap().handshake = 1001;
        // refused: forgotten
        assert!(answer(&mut manager, false).ok);
        assert!(manager.entries[0].keys.is_empty() && script.lock().unwrap().key.is_none());
        // taken: tried at once in the tunnel, but the key of this computer only with a handshake
        manager.entries[0].keys.pending = Some(NEW_KEY);
        assert!(answer(&mut manager, true).ok);
        assert_eq!(script.lock().unwrap().key, Some(NEW_KEY));
        assert_eq!(manager.entries[0].key_in_use(), NEW_KEY);
        assert_eq!(manager.entries[0].keys, OwnKeys { own: None, pending: Some(NEW_KEY) });
        let now = unix_now();
        watch_key(&mut manager, &script, now, 400, now);
        assert_eq!(manager.entries[0].keys, OwnKeys { own: Some(NEW_KEY), pending: None });
        // nothing pending: nothing changes
        assert!(answer(&mut manager, true).ok);
        assert_eq!(manager.entries[0].keys.own, Some(NEW_KEY));
        let missing = manager.handle_locked(Request::WireguardKey { name: "Nowhere".into(), accepted: true }, &OWNER);
        assert_eq!(missing.error_code(), ipc::NOT_FOUND);
        // off: no new key
        manager.down("Office", &OWNER);
        assert_eq!(manager.handle_locked(new_key_request(), &OWNER).error_code(), ipc::INVALID);
    }

    // Any program of the user can say that the server took a key: a key the server has is never lost for it
    #[test]
    fn a_key_the_server_never_took() {
        let file = conf::parse(CONFIG).unwrap().private_key;
        // the tunnel works with the key of this computer, the one the server has
        let (mut manager, script) = office_with(OwnKeys { own: Some(OLD_KEY), pending: None });
        watch_key(&mut manager, &script, 1001, 148, 1001);
        // no new key for the server in its place, and what the app says changes nothing
        assert_eq!(manager.handle_locked(new_key_request(), &OWNER).error_code(), ipc::INVALID);
        manager.entries[0].keys.pending = Some(NEW_KEY);
        assert_eq!(answer(&mut manager, true).error_code(), ipc::INVALID);
        assert_eq!(answer(&mut manager, false).error_code(), ipc::INVALID);
        assert_eq!(script.lock().unwrap().key, None);
        assert_eq!(manager.entries[0].keys, OwnKeys { own: Some(OLD_KEY), pending: Some(NEW_KEY) });

        // in place of the key of the file, which works: the new key is tried, but no handshake comes with it. Back to
        // the key of the file, with the new key still pending
        let (mut manager, script) = office_with(OwnKeys { own: None, pending: Some(NEW_KEY) });
        script.lock().unwrap().handshake = 1001;
        assert!(answer(&mut manager, true).ok);
        assert_eq!(script.lock().unwrap().key, Some(NEW_KEY));
        let since = manager.entries[0].active.as_ref().unwrap().key.since;
        watch_key(&mut manager, &script, since + KEY_SILENCE, 5000, 1001);
        assert_eq!(script.lock().unwrap().key, Some(file));
        assert_eq!(manager.entries[0].keys, OwnKeys { own: None, pending: Some(NEW_KEY) });
        assert_eq!(manager.entries[0].first_key(), file);
    }

    // A key with a handshake becomes the one of this computer, and the one before stays pending
    #[test]
    fn the_key_before_stays() {
        let file = conf::parse(CONFIG).unwrap().private_key;
        let (mut manager, script) = office_with(OwnKeys { own: Some(OLD_KEY), pending: Some(NEW_KEY) });
        manager.entries[0].active.as_mut().unwrap().key = KeyUse::new(NEW_KEY, 1000, 0);
        watch_key(&mut manager, &script, 1000, 148, 1000);
        assert_eq!(manager.entries[0].keys, OwnKeys { own: Some(NEW_KEY), pending: Some(OLD_KEY) });
        // the new key stops working: the key of the file, then the one before, which the server takes
        watch_key(&mut manager, &script, 1000 + KEY_LOST, 9000, 1000);
        assert_eq!(script.lock().unwrap().key, Some(file));
        watch_key(&mut manager, &script, 1000 + KEY_LOST + KEY_SILENCE, 9500, 1000);
        assert_eq!(script.lock().unwrap().key, Some(OLD_KEY));
        let now = 1001 + KEY_LOST + KEY_SILENCE;
        watch_key(&mut manager, &script, now, 9600, now);
        assert_eq!(manager.entries[0].keys, OwnKeys { own: Some(OLD_KEY), pending: Some(NEW_KEY) });
    }

    #[test]
    fn the_vpn_of_another_user() {
        let (mut manager, _) = office();
        #[allow(clippy::default_constructed_unit_structs)]
        let home = Entry::new("Home".into(), store::Id::default(), conf::parse(CONFIG).unwrap(), OwnKeys::default());
        manager.entries.push(home);
        let started = Arc::new(Mutex::new(Vec::new()));
        manager.engine = Box::new(StartEngine(started.clone()));
        // the list says whose it is
        assert!(!manager.list(1)[0].other_user);
        assert!(manager.list(2)[0].other_user && !manager.list(2)[1].other_user);

        // its login, its routes and its keys are of its user only, not of an administrator either
        let host: Ipv4Addr = "10.103.1.1".parse().unwrap();
        let office = || "Office".to_string();
        let requests = || {
            [
                Request::LoggedIn { name: office(), logged_in: true },
                Request::Sign { name: office(), host, challenge: "C".into(), username: "mallory".into(), machine_id: false },
                Request::DeviceKey { name: office() },
                Request::NewWireguardKey { name: office(), host, challenge: "C".into() },
                Request::WireguardKey { name: office(), accepted: true },
            ]
        };
        for client in [&OTHER, &OTHER_ADMIN] {
            for request in requests() {
                let text = format!("{:?}", request);
                assert_eq!(manager.handle_locked(request, client).error_code(), ipc::ACCESS_DENIED, "{}", text);
            }
        }
        // nor turned off, nor by another VPN that goes on
        assert_eq!(manager.handle_locked(Request::Down { name: office() }, &OTHER).error_code(), ipc::ACCESS_DENIED);
        assert_eq!(manager.up("Office", &OTHER).error_code(), ipc::IN_USE);
        assert_eq!(manager.up("Home", &OTHER).error_code(), ipc::IN_USE);
        assert_eq!(on(&manager), ["Office"]);
        assert!(started.lock().unwrap().is_empty());

        // a user who can manage the VPNs, and remove them anyway, can turn it off
        assert_eq!(manager.up("Office", &OTHER_ADMIN).error_code(), ipc::IN_USE);
        assert!(manager.up("Home", &OTHER_ADMIN).ok);
        assert_eq!(on(&manager), ["Home"]);
        assert!(manager.list(1)[1].other_user && !manager.list(2)[1].other_user);
        // now the first user can't, and the other one can
        assert_eq!(manager.down("Home", &OWNER).error_code(), ipc::ACCESS_DENIED);
        assert_eq!(manager.up("Office", &OWNER).error_code(), ipc::IN_USE);
        assert!(manager.down("Home", &OTHER).ok);
        assert!(on(&manager).is_empty());
        assert!(manager.up("Office", &OWNER).ok);
    }

    // Office off, with an engine that turns any tunnel on
    fn office_off() -> (Mutex<Manager>, Arc<Mutex<Vec<String>>>) {
        let (mut manager, _) = office();
        manager.entries[0].active = None;
        let started = Arc::new(Mutex::new(Vec::new()));
        manager.engine = Box::new(StartEngine(started.clone()));
        (Mutex::new(manager), started)
    }

    #[test]
    fn the_servers_are_looked_up_out_of_the_lock() {
        let up = || Request::Up { name: "Office".into() };
        // the apps get their answers meanwhile
        let (manager, started) = office_off();
        let response = handle_with(&manager, up(), &OWNER, |name, config| {
            assert!(manager.try_lock().is_ok(), "the lookup holds the lock of the manager");
            resolve(name, config)
        });
        assert!(response.ok);
        assert_eq!(*started.lock().unwrap(), ["Office"]);

        // replaced meanwhile: looked up again, for the new configuration
        let (manager, started) = office_off();
        let lookups = std::cell::Cell::new(0);
        let response = handle_with(&manager, up(), &OWNER, |name, config| {
            lookups.set(lookups.get() + 1);
            if lookups.get() == 1 {
                lock(&manager).entries[0].revision = next_id();
            }
            resolve(name, config)
        });
        assert!(response.ok);
        assert_eq!((lookups.get(), started.lock().unwrap().len()), (2, 1));

        // replaced every time: given up
        let (manager, started) = office_off();
        let response = handle_with(&manager, up(), &OWNER, |name, config| {
            lock(&manager).entries[0].revision = next_id();
            resolve(name, config)
        });
        assert_eq!(response.error_code(), ipc::FAILED);
        assert!(started.lock().unwrap().is_empty());

        // removed meanwhile
        let (manager, _) = office_off();
        let response = handle_with(&manager, up(), &OWNER, |name, config| {
            lock(&manager).entries.clear();
            resolve(name, config)
        });
        assert_eq!(response.error_code(), ipc::NOT_FOUND);

        // the server can't be found: said, and nothing goes on
        let (manager, started) = office_off();
        let response = handle_with(&manager, up(), &OWNER, |_, _| Err("Can't find the server vpn.example.com.".into()));
        assert_eq!((response.error_code(), response.message()), (ipc::FAILED, "Can't find the server vpn.example.com."));
        assert!(started.lock().unwrap().is_empty());

        // nothing to look up: a VPN that doesn't exist, one that's on, one that can't go on
        let never = |_: &str, _: &Config| -> Result<Vec<Option<Failover>>, String> { panic!("a lookup") };
        let (manager, _) = office_off();
        assert_eq!(handle_with(&manager, Request::Up { name: "Lab".into() }, &OWNER, never).error_code(), ipc::NOT_FOUND);
        assert!(handle_with(&manager, up(), &OWNER, resolve).ok);
        assert!(handle_with(&manager, up(), &OWNER, never).ok);
        assert_eq!(handle_with(&manager, up(), &OTHER, never).error_code(), ipc::IN_USE);
        // the other requests: as under the lock
        assert!(handle_with(&manager, Request::List, &OWNER, never).tunnels[0].up);
    }

    fn disk<T>(work: impl FnOnce(&mut disk::Disk) -> T) -> T {
        disk::DISK.with(|disk| work(&mut disk.borrow_mut()))
    }

    fn import(manager: &mut Manager, name: &str, replace: bool, client: &Client) -> Response {
        manager.handle_locked(Request::Import { name: name.into(), config: CONFIG.into(), replace }, client)
    }

    fn names(manager: &Manager) -> Vec<String> {
        manager.list(1).into_iter().map(|info| info.name).collect()
    }

    #[test]
    fn added_replaced_removed() {
        let (mut manager, _) = office();
        disk(|disk| {
            *disk = disk::Disk::default();
            disk.files.push(("Office".into(), CONFIG.into()));
        });
        let revision = manager.entries[0].revision;
        let remove = |manager: &mut Manager, name: &str| manager.handle_locked(Request::Remove { name: name.into() }, &OTHER_ADMIN);

        // the disk refuses: everything stays as it was, Office on too
        disk(|disk| disk.refuse = true);
        assert_eq!(import(&mut manager, "Home", false, &OTHER_ADMIN).error_code(), ipc::FAILED);
        assert_eq!(import(&mut manager, "Office", true, &OTHER_ADMIN).error_code(), ipc::FAILED);
        assert_eq!(import(&mut manager, "OFFICE", true, &OTHER_ADMIN).error_code(), ipc::FAILED);
        assert_eq!(remove(&mut manager, "Office").error_code(), ipc::FAILED);
        assert_eq!((names(&manager), on(&manager)), (vec!["Office".to_string()], vec!["Office".to_string()]));
        assert_eq!(manager.entries[0].revision, revision);
        assert!(disk(|disk| disk.journal.is_empty()));
        disk(|disk| disk.refuse = false);

        // added; again only to replace it, and only by a user who can manage the VPNs
        assert!(import(&mut manager, "Home", false, &OTHER_ADMIN).ok);
        assert_eq!(import(&mut manager, "home", false, &OTHER_ADMIN).error_code(), ipc::EXISTS);
        assert_eq!(import(&mut manager, "Home", true, &OWNER).error_code(), ipc::ACCESS_DENIED);
        // replaced in another spelling: renamed with its device key, then saved; off, with a new configuration
        assert!(import(&mut manager, "OFFICE", true, &OTHER_ADMIN).ok);
        assert_eq!(names(&manager), ["Home", "OFFICE"]);
        assert!(on(&manager).is_empty());
        assert_ne!(manager.entries[1].revision, revision);
        let journal = ["save Home", "rename Office OFFICE", "rename the device key of Office OFFICE", "save OFFICE"];
        assert_eq!(disk(|disk| disk.journal.clone()), journal);
        assert_eq!(disk(|disk| disk.files.iter().map(|file| file.0.clone()).collect::<Vec<_>>()), ["OFFICE", "Home"]);

        // removed, with its device key
        disk(|disk| disk.journal.clear());
        assert!(remove(&mut manager, "office").ok);
        assert_eq!(names(&manager), ["Home"]);
        assert_eq!(disk(|disk| disk.journal.clone()), ["delete OFFICE", "delete the device key of OFFICE"]);
        assert_eq!(remove(&mut manager, "office").error_code(), ipc::NOT_FOUND);
    }

    #[test]
    fn sessions_of_the_tunnels_on() {
        let (mut manager, _) = office();
        assert_eq!(manager.sessions(), [1]);
        manager.session_ended(2, "another user signed out");
        assert_eq!(manager.sessions(), [1]);
        manager.session_ended(1, "the user signed out");
        assert!(manager.sessions().is_empty());
        assert!(!manager.list(1)[0].up);
    }
}
