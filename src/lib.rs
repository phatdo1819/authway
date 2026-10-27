// A WireGuard client that logs in to the servers that require it (ns-wgauth), for Windows and macOS. One program
// is the app of the users, next to the clock or in the menu bar, and the service that owns the tunnels, as SYSTEM
// or root. The modules without a system in their path are the same on both; the others have one file per system,
// with the same functions.

// the handles of Windows are pointers that this code passes to Windows, never dereferences
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod api;
pub mod client;
pub mod conf;
pub mod failover;
pub mod ipc;
pub mod log;
pub mod manager;
pub mod names;
pub mod product;
pub mod strings;
pub mod time;
pub mod x25519;

// one file per system
#[cfg_attr(target_os = "macos", path = "macos/creds.rs")]
pub mod creds;
#[cfg_attr(target_os = "macos", path = "macos/net.rs")]
pub mod net;
#[cfg_attr(target_os = "macos", path = "macos/service.rs")]
pub mod service;
#[cfg_attr(target_os = "macos", path = "macos/settings.rs")]
pub mod settings;
#[cfg_attr(target_os = "macos", path = "macos/setup.rs")]
pub mod setup;
#[cfg_attr(target_os = "macos", path = "macos/store.rs")]
pub mod store;
#[cfg_attr(target_os = "macos", path = "macos/ui/mod.rs")]
pub mod ui;
#[cfg_attr(target_os = "macos", path = "macos/wg.rs")]
pub mod wg;

// Windows only
#[cfg(windows)]
pub mod reg;
#[cfg(windows)]
pub mod win;

// what the macOS files need, in plain text, tested on every system: the protocol of wireguard-go, and the
// commands for the routes and the DNS servers
#[cfg(any(target_os = "macos", test))]
#[path = "macos/plan.rs"]
pub mod plan;
#[cfg(any(target_os = "macos", test))]
#[path = "macos/uapi.rs"]
pub mod uapi;
