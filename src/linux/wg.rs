// The tunnels on Linux: the WireGuard of the kernel (Linux 5.6 and later), through ip and wg, the WireGuard tools of
// WireGuard LLC (wireguard-tools), as wg-quick uses them. The service gives each tunnel a free interface authwayN, sets
// its configuration with wg, the keys on its standard input, never on a command line, and the network with net.rs.
// The interface goes when the tunnel is dropped; the ones that a service that stopped left go at its next start.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::commands;
use crate::conf::{self, Config};
use crate::log;
use crate::manager::{Engine, PeerStats, Steps, Tunnel};
use crate::names;
use crate::net::{self, Network};
use crate::secret;
use crate::setup;
use crate::store;

fn ip() -> Result<PathBuf, String> {
    setup::tool("ip").ok_or_else(|| "ip isn't installed (iproute2)".to_string())
}

fn wg() -> Result<PathBuf, String> {
    setup::tool("wg").ok_or_else(|| "wg isn't installed (wireguard-tools)".to_string())
}

// ip or wg with its arguments, the input given: its output, or what it wrote as an error
fn run(program: &Path, args: &[String], input: Option<&str>) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{}: {}", program.display(), error))?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(input.as_bytes()).map_err(|error| format!("{}: {}", program.display(), error))?;
    }
    let output = child.wait_with_output().map_err(|error| format!("{}: {}", program.display(), error))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// the WireGuard interfaces of the app on this computer
fn interfaces() -> Vec<String> {
    let Ok(ip) = ip() else { return Vec::new() };
    run(&ip, &commands::link_list_args(), None).map(|text| commands::parse_link_names(&text)).unwrap_or_default()
}

// At the start of the service: the interfaces of a service that stopped without taking them back, with their routes
// and the DNS servers that systemd-resolved had for them
pub fn clean_up() {
    let prefix = names::interface_prefix();
    let Ok(ip) = ip() else { return };
    for name in interfaces().into_iter().filter(|name| name.starts_with(&prefix)) {
        match run(&ip, &commands::link_delete_args(&name), None) {
            Ok(_) => log!("{}: an interface of before, gone", name),
            Err(error) => log!("{}: can't remove an interface of before: {}", name, error),
        }
    }
}

// an interface of the WireGuard of the kernel: it goes when it's dropped
struct Device {
    name: String,
    index: u32,
}

impl Device {
    fn create() -> Result<Device, String> {
        let ip = ip()?;
        wg()?;
        let taken: Vec<String> = interfaces();
        let name = commands::free_interface(&names::interface_prefix(), &taken).ok_or("no interface name is free")?;
        run(&ip, &commands::link_add_args(&name), None).map_err(|error| {
            if error.contains("Unknown device type") || error.contains("not supported") {
                "the kernel of this computer has no WireGuard: it needs Linux 5.6 or later".to_string()
            } else {
                format!("can't create the interface {}: {}", name, error)
            }
        })?;
        // dropped at once if it can't be found, and the interface with it
        let mut device = Device { name, index: 0 };
        device.index = net::interface_index(&device.name)?;
        Ok(device)
    }

    fn peers(&self) -> Result<Vec<PeerStats>, String> {
        let mut answer = run(&wg()?, &commands::wg_dump_args(&self.name), None)?;
        let peers = commands::parse_dump(&answer);
        // it holds the private key
        secret::wipe(&mut answer);
        peers
    }

    // a request whose input holds a key: wiped once sent
    fn set_secret(&self, args: &[String], mut input: String) -> Result<(), String> {
        let result = wg().and_then(|wg| run(&wg, args, Some(&input)));
        secret::wipe(&mut input);
        result.map(|_| ())
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Ok(ip) = ip() {
            if let Err(error) = run(&ip, &commands::link_delete_args(&self.name), None) {
                log!("{}: can't remove the interface: {}", self.name, error);
            }
        }
    }
}

struct KernelTunnel {
    // first: the routes out of the tunnel and the DNS servers go back while the interface is still there
    network: Network,
    device: Device,
    mtu: u32,
}

impl Tunnel for KernelTunnel {
    fn peers(&self) -> Vec<PeerStats> {
        self.device.peers().unwrap_or_else(|error| {
            log!("{}: {}", self.device.name, error);
            Vec::new()
        })
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn interface(&self) -> u32 {
        self.device.index
    }

    fn set_endpoint(&mut self, public_key: &conf::Key, address: SocketAddr) -> Result<(), String> {
        // the new address out of the tunnel first, or the first packets go into it
        self.network.add_server(address.ip());
        wg()
            .and_then(|wg| run(&wg, &commands::wg_endpoint_args(&self.device.name, public_key, &address), None))
            .map(|_| ())
            .map_err(|error| format!("can't change the address of the server: {}", error))
    }

    fn set_private_key(&mut self, key: &conf::Key) -> Result<(), String> {
        self.device
            .set_secret(&commands::wg_private_key_args(&self.device.name), conf::encode_key(key))
            .map_err(|error| format!("can't change the key of the tunnel: {}", error))
    }

    fn after_login(&mut self, on: bool) -> Result<(), String> {
        self.network.after_login(on);
        Ok(())
    }

    fn upkeep(&mut self) {
        self.network.upkeep();
    }
}

pub fn engine() -> Box<dyn Engine> {
    Box::new(KernelEngine)
}

pub struct KernelEngine;

impl Engine for KernelEngine {
    fn start(
        &mut self,
        name: &str,
        _id: &store::Id,
        config: &Config,
        endpoints: &[Option<SocketAddr>],
        steps: &Steps,
    ) -> Result<Box<dyn Tunnel>, String> {
        let device = Device::create()?;
        let mtu = match config.mtu {
            Some(mtu) => u32::from(mtu),
            None => endpoints.iter().flatten().next().map(net::auto_mtu).unwrap_or(net::DEFAULT_MTU),
        };
        device
            .set_secret(&commands::wg_setconf_args(&device.name), commands::wg_config(config, endpoints))
            .map_err(|error| format!("can't configure the tunnel: {}", error))?;
        let network = Network::configure(&device.name, config, mtu, endpoints, steps)?;
        let servers: Vec<String> = endpoints.iter().flatten().map(ToString::to_string).collect();
        log!("{}: {} to {}, MTU {}", name, device.name, servers.join(", "), mtu);
        Ok(Box::new(KernelTunnel { network, device, mtu }))
    }
}
