//! A minimal DNS client.
//!
//! Written by hand rather than pulled from a resolver crate for three reasons:
//! the daemon needs the raw RCODE and the exact latency rather than a
//! `Result<Vec<IpAddr>>`; it must send the query over a socket carrying a
//! specific SO_MARK, which general-purpose resolvers do not expose; and it has
//! to work when the system resolver is exactly what is broken.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use anyhow::{Result, bail};
use tokio::net::UdpSocket;

use super::{ProbeContext, ProbeResult, apply_context, explain_io_error};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl RCode {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => RCode::NoError,
            1 => RCode::FormErr,
            2 => RCode::ServFail,
            3 => RCode::NxDomain,
            4 => RCode::NotImp,
            5 => RCode::Refused,
            other => RCode::Other(other),
        }
    }

    pub fn name(&self) -> String {
        match self {
            RCode::NoError => "NOERROR".into(),
            RCode::FormErr => "FORMERR".into(),
            RCode::ServFail => "SERVFAIL".into(),
            RCode::NxDomain => "NXDOMAIN".into(),
            RCode::NotImp => "NOTIMP".into(),
            RCode::Refused => "REFUSED".into(),
            RCode::Other(v) => format!("RCODE{v}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub addresses: Vec<IpAddr>,
    pub rcode: RCode,
    pub truncated: bool,
    pub authoritative: bool,
    pub answer_count: u16,
    pub duration_ms: u64,
    pub server: SocketAddr,
}

/// Encode a standard recursive query. Uses a fixed-size question section; no
/// EDNS, because the point is to test the resolver path, not to negotiate
/// features with it.
fn encode_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    // QR=0 OPCODE=0 AA=0 TC=0 RD=1, RA=0 Z=0 RCODE=0
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            bail!("DNS label '{label}' exceeds 63 bytes");
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root label
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(buf)
}

/// Walk a (possibly compressed) domain name and return the offset just past
/// it. We never need the decoded name itself, only to skip it correctly.
fn skip_name(buf: &[u8], mut offset: usize) -> Result<usize> {
    let mut jumped = false;
    let mut steps = 0;
    loop {
        if offset >= buf.len() {
            bail!("DNS name runs past the end of the message");
        }
        let len = buf[offset];
        if len & 0xc0 == 0xc0 {
            // Compression pointer: two bytes, and the name ends here.
            if offset + 1 >= buf.len() {
                bail!("truncated DNS compression pointer");
            }
            if !jumped {
                offset += 2;
            }
            return Ok(offset);
        }
        offset += 1;
        if len == 0 {
            return Ok(offset);
        }
        offset += len as usize;
        steps += 1;
        if steps > 128 {
            bail!("DNS name has too many labels; refusing to loop");
        }
        jumped = false;
    }
}

fn decode_response(
    buf: &[u8],
    expect_id: u16,
    qtype: u16,
) -> Result<(Vec<IpAddr>, RCode, bool, bool, u16)> {
    if buf.len() < 12 {
        bail!("DNS response is shorter than a header");
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expect_id {
        bail!("DNS response id {id} does not match the query id {expect_id}");
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = RCode::from_u8((flags & 0x000f) as u8);
    let truncated = flags & 0x0200 != 0;
    let authoritative = flags & 0x0400 != 0;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(buf, offset)?;
        offset += 4; // QTYPE + QCLASS
    }

    let mut addresses = Vec::new();
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }
        offset = skip_name(buf, offset)?;
        if offset + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > buf.len() {
            break;
        }
        let rdata = &buf[offset..offset + rdlength];
        // CNAMEs in the chain are skipped; only the address records matter.
        if rtype == qtype {
            match (qtype, rdlength) {
                (TYPE_A, 4) => {
                    addresses.push(IpAddr::V4(Ipv4Addr::new(
                        rdata[0], rdata[1], rdata[2], rdata[3],
                    )));
                }
                (TYPE_AAAA, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(rdata);
                    addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        offset += rdlength;
    }

    Ok((addresses, rcode, truncated, authoritative, ancount))
}

/// Send one query over UDP and wait for the reply.
pub async fn query(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    ctx: &ProbeContext,
) -> Result<DnsAnswer> {
    // A fixed id would let a stale reply from a previous probe be accepted.
    let id: u16 = (crate::util::monotonic_ns() as u16) | 1;
    let query = encode_query(id, name, qtype)?;

    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let std_socket = std::net::UdpSocket::bind(bind)?;
    std_socket.set_nonblocking(true)?;
    {
        use std::os::fd::AsRawFd;
        apply_context(std_socket.as_raw_fd(), ctx)?;
    }
    let socket = UdpSocket::from_std(std_socket)?;

    let started = Instant::now();
    socket.send_to(&query, server).await?;

    let mut buf = vec![0u8; 4096];
    let received = tokio::time::timeout(ctx.timeout, socket.recv(&mut buf)).await;
    let duration_ms = started.elapsed().as_millis() as u64;

    let len = match received {
        Ok(Ok(len)) => len,
        Ok(Err(e)) => bail!("{}", explain_io_error(&e)),
        Err(_) => bail!("no response within {} ms", ctx.timeout.as_millis()),
    };

    let (addresses, rcode, truncated, authoritative, answer_count) =
        decode_response(&buf[..len], id, qtype)?;

    Ok(DnsAnswer {
        addresses,
        rcode,
        truncated,
        authoritative,
        answer_count,
        duration_ms,
        server,
    })
}

/// Run a query and package it as a `ProbeResult`.
pub async fn probe(server: SocketAddr, name: &str, qtype: u16, ctx: &ProbeContext) -> ProbeResult {
    let type_name = if qtype == TYPE_A { "A" } else { "AAAA" };
    let started = Instant::now();

    match query(server, name, qtype, ctx).await {
        Ok(answer) => {
            let addresses: Vec<String> = answer.addresses.iter().map(|a| a.to_string()).collect();
            let ok = answer.rcode == RCode::NoError && !answer.addresses.is_empty();
            let detail = if ok {
                format!(
                    "{type_name} {name} -> {} in {} ms",
                    addresses.join(", "),
                    answer.duration_ms
                )
            } else if answer.rcode == RCode::NoError {
                format!("{type_name} {name} returned NOERROR with no records")
            } else {
                format!("{type_name} {name} returned {}", answer.rcode.name())
            };

            let mut result = if ok {
                ProbeResult::success(answer.duration_ms, detail)
            } else {
                ProbeResult::failure(answer.duration_ms, detail)
            };
            result = result
                .with("server", answer.server.to_string())
                .with("rcode", answer.rcode.name())
                .with("answers", answer.answer_count.to_string())
                .with("authoritative", answer.authoritative.to_string())
                .with("routing", ctx.describe());
            if !addresses.is_empty() {
                result = result.with("addresses", addresses.join(", "));
            }
            if answer.truncated {
                result = result.with("truncated", "yes (response exceeded 512 bytes over UDP)");
            }
            result
        }
        Err(e) => ProbeResult::failure(
            started.elapsed().as_millis() as u64,
            format!("{type_name} {name} failed: {e}"),
        )
        .with("server", server.to_string())
        .with("routing", ctx.describe()),
    }
}

/// The well-known DNS64 discovery query from RFC 7050. `ipv4only.arpa` has
/// only A records; if a AAAA query for it comes back with addresses, a DNS64
/// server synthesised them, and the leading bytes are the NAT64 prefix.
pub const DNS64_PROBE_NAME: &str = "ipv4only.arpa";

/// RFC 7050's well-known IPv4 addresses embedded in the synthesised answers.
const WKA: [Ipv4Addr; 2] = [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

/// Recover the NAT64 prefix from a synthesised AAAA record. The well-known
/// IPv4 address can be embedded at any of the standard prefix lengths, so the
/// prefix length falls out of where it is found.
pub fn extract_nat64_prefix(addr: Ipv6Addr) -> Option<(Ipv6Addr, u8)> {
    let octets = addr.octets();
    // Offsets and prefix lengths defined by RFC 6052.
    for (offset, prefix_len) in [(4usize, 32u8), (5, 40), (6, 48), (8, 56), (9, 64), (12, 96)] {
        // The 40..64 bit variants skip the reserved byte at offset 8.
        let mut candidate = [0u8; 4];
        let mut idx = offset;
        let mut filled = 0;
        while filled < 4 && idx < 16 {
            if idx == 8 && prefix_len < 96 && prefix_len != 32 {
                // Bits 64..71 are reserved and must be zero; skip them.
                idx += 1;
                continue;
            }
            candidate[filled] = octets[idx];
            filled += 1;
            idx += 1;
        }
        if filled < 4 {
            continue;
        }
        let embedded = Ipv4Addr::from(candidate);
        if WKA.contains(&embedded) {
            let mut prefix = octets;
            for byte in prefix.iter_mut().skip((prefix_len as usize) / 8) {
                *byte = 0;
            }
            return Some((Ipv6Addr::from(prefix), prefix_len));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_a_query() {
        let q = encode_query(0x1234, "example.com", TYPE_A).unwrap();
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD set
        assert_eq!(&q[4..6], &[0x00, 0x01]); // one question
        // 7"example" 3"com" 0
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        assert_eq!(&q[25..27], &[0x00, 0x01]); // QTYPE A
    }

    #[test]
    fn trailing_dot_does_not_produce_an_empty_label() {
        let with = encode_query(1, "example.com.", TYPE_A).unwrap();
        let without = encode_query(1, "example.com", TYPE_A).unwrap();
        assert_eq!(with, without);
    }

    #[test]
    fn decodes_an_a_response() {
        let mut msg = Vec::new();
        msg.extend_from_slice(&0xabcdu16.to_be_bytes());
        msg.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA, NOERROR
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        // Question: example.com A IN
        msg.push(7);
        msg.extend_from_slice(b"example");
        msg.push(3);
        msg.extend_from_slice(b"com");
        msg.push(0);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        // Answer using a compression pointer back to the question name.
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[93, 184, 216, 34]);

        let (addrs, rcode, truncated, _auth, count) =
            decode_response(&msg, 0xabcd, TYPE_A).unwrap();
        assert_eq!(rcode, RCode::NoError);
        assert!(!truncated);
        assert_eq!(count, 1);
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }

    #[test]
    fn rejects_a_mismatched_transaction_id() {
        let mut msg = vec![0u8; 12];
        msg[0] = 0x00;
        msg[1] = 0x01;
        assert!(decode_response(&msg, 0xabcd, TYPE_A).is_err());
    }

    #[test]
    fn reports_nxdomain() {
        let mut msg = vec![0u8; 12];
        msg[0..2].copy_from_slice(&0x1111u16.to_be_bytes());
        msg[2..4].copy_from_slice(&0x8183u16.to_be_bytes()); // NXDOMAIN
        let (addrs, rcode, _, _, _) = decode_response(&msg, 0x1111, TYPE_A).unwrap();
        assert_eq!(rcode, RCode::NxDomain);
        assert!(addrs.is_empty());
    }

    #[test]
    fn extracts_a_96_bit_nat64_prefix() {
        // 64:ff9b::/96 with 192.0.0.170 embedded in the last 32 bits.
        let addr: Ipv6Addr = "64:ff9b::c000:00aa".parse().unwrap();
        let (prefix, len) = extract_nat64_prefix(addr).expect("prefix should be found");
        assert_eq!(len, 96);
        assert_eq!(prefix, "64:ff9b::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn a_native_aaaa_yields_no_nat64_prefix() {
        let addr: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        assert!(extract_nat64_prefix(addr).is_none());
    }
}
