// A WireGuard client for Windows that logs in to the servers that require it (ns-wgauth): one exe that is the
// app next to the clock, for the users, and the service that owns the tunnels, as SYSTEM

// the handles of Windows are pointers that this code passes to Windows, never dereferences
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod api;
pub mod conf;
pub mod creds;
pub mod failover;
pub mod ipc;
pub mod log;
pub mod names;
pub mod net;
pub mod product;
pub mod reg;
pub mod service;
pub mod settings;
pub mod setup;
pub mod store;
pub mod strings;
pub mod ui;
pub mod wg;
pub mod win;
pub mod x25519;
