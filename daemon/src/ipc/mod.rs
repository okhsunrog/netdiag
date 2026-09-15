//! IPC between the Compose app and this daemon: framing, authorization,
//! listening socket, and per-connection dispatch.

pub mod auth;
pub mod listener;
pub mod session;

/// Framing is part of the wire contract, not of this daemon.
pub use netdiag_ipc::codec;
