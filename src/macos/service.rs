// The service on macOS, a launchd job as root: it keeps the configurations of the tunnels and turns them on and off
// for the app of the users, through its socket. The session of a tunnel is the user who turned it on; macOS doesn't
// tell a service when a user logs out, so a tunnel goes off when the app of its user stops asking for the list.

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::ipc::{self, Request, Response};
use crate::log;
use crate::manager::{self, Client, Engine, Manager};
use crate::names;
use crate::net;
use crate::settings;
use crate::setup;

// the app lists at least every 10 seconds while it runs
const HEARTBEAT: Duration = Duration::from_secs(120);
// a client that doesn't send its request
const REQUEST_TIME: Duration = Duration::from_secs(10);

#[cfg(not(feature = "testing"))]
fn engine() -> Box<dyn Engine> {
    Box::new(crate::wg::GoEngine)
}

#[cfg(feature = "testing")]
fn engine() -> Box<dyn Engine> {
    Box::new(manager::fake::FakeEngine)
}

fn client_of(uid: u32) -> Client {
    let can_manage = if cfg!(feature = "testing") {
        std::env::var("AUTHWAY_TEST_DENY").is_err()
    } else {
        // root: the app asked macOS for an administrator, or sudo
        uid == 0 || settings::users_can_manage()
    };
    Client { session: uid, can_manage }
}

struct Server {
    manager: Mutex<Manager>,
    stopping: AtomicBool,
    // when each user last asked something
    seen: Mutex<HashMap<u32, Instant>>,
}

impl Server {
    fn new() -> Arc<Server> {
        Arc::new(Server {
            manager: Mutex::new(Manager::load(engine())),
            stopping: AtomicBool::new(false),
            seen: Mutex::new(HashMap::new()),
        })
    }

    fn serve_client(&self, mut stream: UnixStream) {
        let _ = stream.set_read_timeout(Some(REQUEST_TIME));
        let _ = stream.set_write_timeout(Some(REQUEST_TIME));
        let response = match (ipc::peer_uid(&stream), ipc::read_from::<Request>(&mut stream)) {
            (None, _) => Response::failure(ipc::ACCESS_DENIED, "Can't know who asks."),
            (_, Err(error)) => Response::failure(ipc::INVALID, error),
            (Some(uid), Ok(request)) => {
                self.seen.lock().unwrap_or_else(|error| error.into_inner()).insert(uid, Instant::now());
                let client = client_of(uid);
                let mut manager = self.manager.lock().unwrap_or_else(|error| error.into_inner());
                manager.handle(request, &client)
            }
        };
        if let Err(error) = ipc::write_to(&mut stream, &response) {
            log!("{}", error);
        }
    }

    // a connection per request, each on its own thread
    fn listen(self: Arc<Self>, listener: UnixListener) {
        for stream in listener.incoming() {
            if self.stopping.load(Ordering::SeqCst) {
                break;
            }
            match stream {
                Ok(stream) => {
                    let server = self.clone();
                    thread::spawn(move || server.serve_client(stream));
                }
                Err(error) => {
                    log!("can't accept a connection: {}", error);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    // the tunnels of the users whose app is gone: logged out, or quit without turning them off
    fn forget_gone(&self, manager: &mut Manager, now: Instant) {
        let seen = self.seen.lock().unwrap_or_else(|error| error.into_inner()).clone();
        for session in manager.sessions() {
            let gone = seen.get(&session).is_none_or(|last| now.saturating_duration_since(*last) > HEARTBEAT);
            if gone {
                manager.session_ended(session, "the app of the user stopped");
            }
        }
    }

    fn watch(&self) {
        manager::watch_loop(&self.manager, &self.stopping, |manager, now| {
            self.forget_gone(manager, now);
            manager.upkeep();
        });
    }

    // the socket waits for a connection: one wakes it up
    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _wake = UnixStream::connect(names::socket_path());
        self.manager.lock().unwrap_or_else(|error| error.into_inner()).stop();
    }
}

// The socket, for every user: only root can create it in /var/run, and the app checks that it's root's
fn bind() -> Result<UnixListener, String> {
    let path = names::socket_path();
    match fs::symlink_metadata(&path) {
        Ok(existing) if existing.file_type().is_socket() => {
            // a service still answers on it?
            if UnixStream::connect(&path).is_ok() {
                return Err(format!("another service answers on {}", path));
            }
            fs::remove_file(&path).map_err(|error| format!("can't remove the old {}: {}", path, error))?;
        }
        Ok(_) => return Err(format!("{} isn't a socket", path)),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(format!("can't check {}: {}", path, error)),
    }
    let listener = UnixListener::bind(&path).map_err(|error| format!("can't create {}: {}", path, error))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
        .map_err(|error| format!("can't open {} to the users: {}", path, error))?;
    Ok(listener)
}

pub fn log_path() -> PathBuf {
    setup::service_log()
}

// SIGTERM from launchd, SIGINT from a console: blocked in every thread, which inherit the mask, and waited for by one
fn block_signals() -> libc::sigset_t {
    unsafe {
        let mut signals: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, libc::SIGTERM);
        libc::sigaddset(&mut signals, libc::SIGINT);
        libc::sigaddset(&mut signals, libc::SIGHUP);
        libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut());
        signals
    }
}

fn wait_signal(signals: &libc::sigset_t) -> i32 {
    let mut signal = 0;
    loop {
        if unsafe { libc::sigwait(signals, &mut signal) } == 0 {
            return signal;
        }
    }
}

fn serve(started: &str) -> i32 {
    let signals = block_signals();
    log::init(log_path());
    log!("{} {}: {}", names::PRODUCT, names::VERSION, started);
    // the DNS servers of a service that stopped without putting them back
    net::restore_dns_backup();
    let listener = match bind() {
        Ok(listener) => listener,
        Err(error) => {
            log!("{}", error);
            return 1;
        }
    };
    let server = Server::new();
    let listening = {
        let server = server.clone();
        thread::spawn(move || server.listen(listener))
    };
    let watcher = {
        let server = server.clone();
        thread::spawn(move || server.watch())
    };
    let signal = wait_signal(&signals);
    log!("signal {}: the service stops", signal);
    server.stop();
    let _ = listening.join();
    let _ = watcher.join();
    let _ = fs::remove_file(names::socket_path());
    log!("service stopped");
    0
}

// Started by launchd: --service
pub fn run() -> i32 {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("this is the service of {}: launchd starts it as root", names::PRODUCT);
        return 1;
    }
    serve("service started")
}

// The service as the user, with fake tunnels, for the tests: until it gets SIGTERM or Ctrl+C
#[cfg(feature = "testing")]
pub fn run_console() -> i32 {
    serve("test service started")
}
