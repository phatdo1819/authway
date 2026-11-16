// A WireGuard client that logs in to the servers that require it (ns-wgauth), for Windows, macOS and Linux. One
// program is the app of the users, next to the clock, in the menu bar or in the tray, and the service that owns the
// tunnels, as SYSTEM or root. The modules without a system in their path are the same on all of them; the others
// have one file per system, with the same functions, and unix/ the ones that macOS and Linux share.

// the handles of Windows are pointers that this code passes to Windows, never dereferences
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod api;
pub mod client;
pub mod conf;
pub mod device;
pub mod digest;
pub mod failover;
pub mod ipc;
pub mod log;
pub mod manager;
pub mod names;
pub mod product;
pub mod secret;
pub mod strings;
pub mod time;
pub mod x25519;

// one file per system
#[cfg_attr(target_os = "macos", path = "macos/creds.rs")]
#[cfg_attr(target_os = "linux", path = "linux/creds.rs")]
pub mod creds;
#[cfg_attr(target_os = "macos", path = "macos/devkey.rs")]
#[cfg_attr(target_os = "linux", path = "linux/devkey.rs")]
pub mod devkey;
#[cfg_attr(target_os = "macos", path = "macos/net.rs")]
#[cfg_attr(target_os = "linux", path = "linux/net.rs")]
pub mod net;
#[cfg_attr(unix, path = "unix/service.rs")]
pub mod service;
#[cfg_attr(target_os = "macos", path = "macos/settings.rs")]
#[cfg_attr(target_os = "linux", path = "linux/settings.rs")]
pub mod settings;
#[cfg_attr(target_os = "macos", path = "macos/setup.rs")]
#[cfg_attr(target_os = "linux", path = "linux/setup.rs")]
pub mod setup;
#[cfg_attr(unix, path = "unix/store.rs")]
pub mod store;
#[cfg_attr(target_os = "macos", path = "macos/ui/mod.rs")]
#[cfg_attr(target_os = "linux", path = "linux/ui/mod.rs")]
pub mod ui;
#[cfg_attr(target_os = "macos", path = "macos/wg.rs")]
#[cfg_attr(target_os = "linux", path = "linux/wg.rs")]
pub mod wg;

// Windows only
#[cfg(windows)]
pub mod reg;
#[cfg(windows)]
pub mod win;

// what the macOS and Linux files need, in plain text, tested on every system: the protocol of wireguard-go, the
// routes of a tunnel and the commands for the routes and the DNS servers
#[cfg(any(unix, test))]
#[path = "macos/plan.rs"]
pub mod plan;
#[cfg(any(target_os = "macos", test))]
#[path = "macos/uapi.rs"]
pub mod uapi;
#[cfg(any(target_os = "linux", test))]
#[path = "linux/commands.rs"]
pub mod commands;
