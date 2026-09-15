//! Generated protobuf types.
//!
//! Everything that crosses the IPC boundary lives here and nowhere else: these
//! types are generated from `proto/netdiag/v1/*.proto` at build time, so the
//! schema is the single source of truth for both this daemon and the Android
//! app. Never hand-write a struct that mirrors one of these.

#![allow(clippy::all)]
#![allow(clippy::doc_overindented_list_items)]

include!(concat!(env!("OUT_DIR"), "/netdiag.v1.rs"));

/// Protocol version this build speaks. Bump only for changes that older
/// clients cannot tolerate; additive schema changes do not need a bump.
pub const PROTOCOL_VERSION: u32 = 1;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

impl IpAddress {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self {
                addr: v4.octets().to_vec(),
            },
            IpAddr::V6(v6) => Self {
                addr: v6.octets().to_vec(),
            },
        }
    }

    pub fn to_ip(&self) -> Option<IpAddr> {
        match self.addr.len() {
            4 => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&self.addr);
                Some(IpAddr::V4(Ipv4Addr::from(b)))
            }
            16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&self.addr);
                Some(IpAddr::V6(Ipv6Addr::from(b)))
            }
            _ => None,
        }
    }

    pub fn is_set(&self) -> bool {
        matches!(self.addr.len(), 4 | 16)
    }

    pub fn display(&self) -> String {
        match self.to_ip() {
            Some(ip) => ip.to_string(),
            None => "-".to_string(),
        }
    }
}

impl From<IpAddr> for IpAddress {
    fn from(ip: IpAddr) -> Self {
        Self::from_ip(ip)
    }
}

impl IpPrefix {
    pub fn new(ip: IpAddr, prefix_len: u8) -> Self {
        Self {
            address: Some(IpAddress::from_ip(ip)),
            prefix_len: prefix_len as u32,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        self.address.as_ref().and_then(|a| a.to_ip())
    }

    pub fn display(&self) -> String {
        match self.ip() {
            Some(ip) => format!("{}/{}", ip, self.prefix_len),
            None => format!("*/{}", self.prefix_len),
        }
    }
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code as i32,
            message: message.into(),
            detail: String::new(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    pub fn kernel(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Kernel, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::internal(e.to_string()).with_detail(format!("{e:?}"))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::kernel(e.to_string()).with_detail(format!("{:?}", e.kind()))
    }
}
