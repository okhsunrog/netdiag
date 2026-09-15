//! The netdiag IPC contract, as Rust.
//!
//! This crate is everything both sides of the Unix socket need and nothing
//! either side needs alone: the generated protobuf types, the length-delimited
//! framing, and a client.
//!
//! It exists because there are two frontends. The Compose app regenerates the
//! same `.proto` files through the Gradle protobuf plugin and talks to the
//! daemon over Kotlin; the Slint app is Rust and can simply link this. Keeping
//! the framing and the client here means the Rust frontend shares the daemon's
//! own implementation rather than carrying a second one that can drift from it.

pub mod client;
pub mod codec;
pub mod proto;

pub use proto::PROTOCOL_VERSION;
