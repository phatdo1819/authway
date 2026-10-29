// The tunnels on macOS: wireguard-go, the WireGuard of WireGuard LLC in user space, one process per tunnel started
// by the service, next to it and unchanged. The service gives it a free interface utunN, sets the configuration
// through its control socket, /var/run/wireguard/utunN.sock (uapi.rs), and the network with net.rs.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::conf::{self, Config};
use crate::log;
use crate::manager::{Engine, PeerStats, Steps, Tunnel};
use crate::net::{self, Network};
use crate::store;
use crate::{setup, uapi};

const RUN_DIR: &str = "/var/run/wireguard";
const START_TIME: Duration = Duration::from_secs(10);
const STOP_TIME: Duration = Duration::from_secs(3);
const ANSWER_TIME: Duration = Duration::from_secs(5);
const MAX_ANSWER: u64 = 1024 * 1024;
// another program can take the same utun meanwhile: the next one then
const ATTEMPTS: usize = 3;
const MAX_UTUN: u32 = 256;

fn wipe(text: String) {
    let mut bytes = text.into_bytes();
    for byte in bytes.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

// a wireguard-go and its interface: both go when it's dropped
pub struct Device {
    child: Child,
    pub name: String,
    pub index: u32,
    socket: PathBuf,
}

// the first utun that no interface has: wireguard-go gets its name, so its socket is known
fn free_utun() -> Result<String, String> {
    (0..MAX_UTUN)
        .map(|number| format!("utun{}", number))
        .find(|name| net::interface_index(name).is_err())
        .ok_or_else(|| "no utun interface is free".to_string())
}

// its output, in the log of the service
fn forward(tunnel: String, stream: impl Read + Send + 'static) {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            if !line.trim().is_empty() {
                log!("{}: wireguard-go: {}", tunnel, line.trim());
            }
        }
    });
}

impl Device {
    pub fn start(tunnel: &str) -> Result<Device, String> {
        let program = setup::wireguard_go();
        if !program.exists() {
            return Err(format!("{} is missing: install the app again", program.display()));
        }
        fs::create_dir_all(RUN_DIR).map_err(|error| format!("can't create {}: {}", RUN_DIR, error))?;
        let mut attempt = 1;
        loop {
            match Device::start_on(tunnel, &program, &free_utun()?) {
                Err(error) if attempt < ATTEMPTS => {
                    log!("{}: {}, again", tunnel, error);
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    fn start_on(tunnel: &str, program: &Path, name: &str) -> Result<Device, String> {
        let mut child = Command::new(program)
            .args(["-f", name])
            .env("LOG_LEVEL", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("can't start wireguard-go: {}", error))?;
        if let Some(output) = child.stdout.take() {
            forward(tunnel.to_string(), output);
        }
        if let Some(output) = child.stderr.take() {
            forward(tunnel.to_string(), output);
        }
        let socket = Path::new(RUN_DIR).join(format!("{}.sock", name));
        let started = Instant::now();
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("wireguard-go stopped on {}: {}", name, status));
            }
            // the socket comes after the interface
            if socket.exists() {
                if let Ok(index) = net::interface_index(name) {
                    return Ok(Device { child, name: name.to_string(), index, socket });
                }
            }
            if started.elapsed() > START_TIME {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("wireguard-go didn't create {}", name));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    // a request and its answer, up to the empty line
    fn exchange(&self, request: &str) -> Result<String, String> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|error| format!("can't reach wireguard-go: {}", error))?;
        let _ = stream.set_read_timeout(Some(ANSWER_TIME));
        let _ = stream.set_write_timeout(Some(ANSWER_TIME));
        stream.write_all(request.as_bytes()).map_err(|error| format!("can't write to wireguard-go: {}", error))?;
        let mut answer = String::new();
        let mut reader = BufReader::new(stream.take(MAX_ANSWER));
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) if line == "\n" => break,
                Ok(_) => answer.push_str(&line),
                Err(error) => return Err(format!("can't read from wireguard-go: {}", error)),
            }
        }
        Ok(answer)
    }

    // a request that only sets: the answer holds no secret
    fn set(&self, request: &str) -> Result<(), String> {
        uapi::check_errno(&self.exchange(request)?)
    }

    fn peers(&self) -> Result<Vec<PeerStats>, String> {
        let answer = self.exchange(uapi::GET)?;
        let peers = uapi::parse_get(&answer);
        // it holds the private key
        wipe(answer);
        peers
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // as at the end of wg-quick: wireguard-go takes the interface and its socket away
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let started = Instant::now();
        while started.elapsed() < STOP_TIME {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct GoTunnel {
    // first: the routes out of the tunnel and the DNS servers go back while the interface is still there
    network: Network,
    device: Device,
    mtu: u32,
}

impl Tunnel for GoTunnel {
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
        self.device
            .set(&uapi::set_endpoint(public_key, &address))
            .map_err(|error| format!("can't change the address of the server: {}", error))
    }

    fn after_login(&mut self, on: bool) -> Result<(), String> {
        self.network.after_login(on);
        Ok(())
    }

    fn upkeep(&mut self) {
        self.network.upkeep();
    }
}

pub struct GoEngine;

impl Engine for GoEngine {
    fn start(
        &mut self,
        name: &str,
        _id: &store::Id,
        config: &Config,
        endpoints: &[Option<SocketAddr>],
        steps: &Steps,
    ) -> Result<Box<dyn Tunnel>, String> {
        let device = Device::start(name)?;
        let mtu = match config.mtu {
            Some(mtu) => u32::from(mtu),
            None => endpoints.iter().flatten().next().map(net::auto_mtu).unwrap_or(net::DEFAULT_MTU),
        };
        let request = uapi::set_config(config, endpoints);
        let result = device.set(&request);
        wipe(request);
        result.map_err(|error| format!("can't configure the tunnel: {}", error))?;
        let network = Network::configure(&device.name, config, mtu, endpoints, steps)?;
        let servers: Vec<String> = endpoints.iter().flatten().map(ToString::to_string).collect();
        log!("{}: {} to {}, MTU {}", name, device.name, servers.join(", "), mtu);
        Ok(Box::new(GoTunnel { network, device, mtu }))
    }
}
