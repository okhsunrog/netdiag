//! IPC between the Compose app and this daemon: framing, authorization,
//! listening socket, and per-connection dispatch.

pub mod auth;
pub mod codec;
pub mod listener;
pub mod session;
