//! A deliberately minimal TLS reachability probe.
//!
//! This sends a real ClientHello and checks that a ServerHello (or an alert)
//! comes back. It does not validate certificates and does not complete the
//! handshake, and that is the point: the question being answered is "does a
//! TLS conversation survive this path?", not "is this server trustworthy?".
//!
//! Doing it this way keeps a TLS stack and a root certificate store out of the
//! daemon, and it makes two failure modes visible that a normal client library
//! would hide. A connection that opens but produces no ServerHello is the
//! classic signature of a PMTU black hole, because the ClientHello is the
//! first packet large enough to hit it. A TCP RST or a handshake_failure alert
//! right after the ClientHello is what SNI-based filtering looks like.

use std::net::SocketAddr;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ProbeContext, ProbeResult, explain_io_error, tcp};

/// Build a TLS 1.2/1.3-compatible ClientHello with SNI. Kept byte-explicit so
/// it is auditable; there is no negotiation logic to get wrong.
fn client_hello(server_name: &str) -> Vec<u8> {
    let mut extensions = Vec::new();

    // server_name (0x0000)
    if !server_name.is_empty() && server_name.parse::<std::net::IpAddr>().is_err() {
        let host = server_name.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // list length
        sni.push(0); // host_name type
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
    }

    // supported_versions (0x002b): TLS 1.3 and TLS 1.2
    let versions: [u8; 5] = [0x04, 0x03, 0x04, 0x03, 0x03];
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&(versions.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&versions);

    // supported_groups (0x000a): x25519, secp256r1
    let groups: [u8; 6] = [0x00, 0x04, 0x00, 0x1d, 0x00, 0x17];
    extensions.extend_from_slice(&0x000au16.to_be_bytes());
    extensions.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&groups);

    // signature_algorithms (0x000d): ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256
    let sigalgs: [u8; 6] = [0x00, 0x04, 0x04, 0x03, 0x08, 0x04];
    extensions.extend_from_slice(&0x000du16.to_be_bytes());
    extensions.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sigalgs);

    // key_share (0x0033) with an x25519 entry.
    //
    // TLS 1.3 servers reject a ClientHello that offers 1.3 without one, so
    // leaving it out makes every modern server answer with an alert and the
    // probe reports a failure that is entirely our own fault. The key is not
    // real — the handshake is abandoned after the ServerHello — but every
    // 32-byte string is a syntactically valid x25519 public key, so the server
    // gets far enough to answer.
    let mut key_share_entry = Vec::with_capacity(4 + 32);
    key_share_entry.extend_from_slice(&0x001du16.to_be_bytes()); // x25519
    key_share_entry.extend_from_slice(&32u16.to_be_bytes());
    let seed = crate::util::monotonic_ns();
    for i in 0..32u64 {
        key_share_entry.push((seed.rotate_left(i as u32 % 63) ^ i.wrapping_mul(97)) as u8);
    }
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&((key_share_entry.len() + 2) as u16).to_be_bytes());
    extensions.extend_from_slice(&(key_share_entry.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_share_entry);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version TLS 1.2
    // 32 bytes of client random. A monotonic counter is plenty: this handshake
    // is never completed, so the randomness has no security role.
    let seed = crate::util::monotonic_ns();
    for i in 0..32u64 {
        body.push(((seed >> (i % 56)) ^ i.wrapping_mul(31)) as u8);
    }
    body.push(0); // empty session id
    let cipher_suites: [u8; 8] = [
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2f, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
    body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_suites);
    body.push(1); // one compression method
    body.push(0); // null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let len = body.len();
    handshake.push((len >> 16) as u8);
    handshake.push((len >> 8) as u8);
    handshake.push(len as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16); // handshake
    record.extend_from_slice(&0x0301u16.to_be_bytes()); // record version TLS 1.0
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// What came back on the wire.
#[derive(Debug, PartialEq, Eq)]
enum HelloReply {
    ServerHello,
    Alert { level: u8, description: u8 },
    NotTls,
    Empty,
}

fn classify_reply(buf: &[u8]) -> HelloReply {
    if buf.is_empty() {
        return HelloReply::Empty;
    }
    match buf[0] {
        0x16 if buf.len() >= 6 && buf[5] == 0x02 => HelloReply::ServerHello,
        0x16 => HelloReply::NotTls,
        0x15 if buf.len() >= 7 => HelloReply::Alert {
            level: buf[5],
            description: buf[6],
        },
        _ => HelloReply::NotTls,
    }
}

fn alert_name(description: u8) -> &'static str {
    match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        109 => "missing_extension",
        112 => "unrecognized_name",
        120 => "no_application_protocol",
        _ => "unknown alert",
    }
}

pub async fn probe(target: SocketAddr, server_name: &str, ctx: &ProbeContext) -> ProbeResult {
    let started = Instant::now();

    let mut stream = match tcp::connect_stream(target, ctx).await {
        Ok(s) => s,
        Err(e) => {
            return ProbeResult::failure(
                started.elapsed().as_millis() as u64,
                format!("TCP connect to {target} failed: {}", explain_io_error(&e)),
            )
            .with("routing", ctx.describe());
        }
    };
    let tcp_ms = started.elapsed().as_millis() as u64;

    let hello = client_hello(server_name);
    if let Err(e) = stream.write_all(&hello).await {
        return ProbeResult::failure(
            started.elapsed().as_millis() as u64,
            format!("could not send the ClientHello: {}", explain_io_error(&e)),
        )
        .with("tcp_connect_ms", tcp_ms.to_string())
        .with("routing", ctx.describe());
    }

    let mut buf = vec![0u8; 1024];
    let read = tokio::time::timeout(ctx.timeout, stream.read(&mut buf)).await;
    let duration_ms = started.elapsed().as_millis() as u64;

    let evidence = |r: ProbeResult| {
        r.with("target", target.to_string())
            .with("sni", server_name.to_string())
            .with("client_hello_bytes", hello.len().to_string())
            .with("tcp_connect_ms", tcp_ms.to_string())
            .with("routing", ctx.describe())
    };

    match read {
        Ok(Ok(0)) => evidence(ProbeResult::failure(
            duration_ms,
            "the peer closed the connection without answering the ClientHello".to_string(),
        )),
        Ok(Ok(n)) => match classify_reply(&buf[..n]) {
            HelloReply::ServerHello => evidence(ProbeResult::success(
                duration_ms,
                format!("TLS ServerHello received in {duration_ms} ms"),
            )),
            HelloReply::Alert { level, description } => evidence(
                ProbeResult::failure(
                    duration_ms,
                    format!(
                        "TLS alert instead of a ServerHello: {} ({description}, level {level})",
                        alert_name(description)
                    ),
                )
                .with("alert_description", description.to_string()),
            ),
            HelloReply::NotTls => evidence(ProbeResult::failure(
                duration_ms,
                "the peer answered with something that is not a TLS handshake".to_string(),
            )),
            HelloReply::Empty => evidence(ProbeResult::failure(
                duration_ms,
                "empty reply to the ClientHello".to_string(),
            )),
        },
        Ok(Err(e)) => evidence(ProbeResult::failure(
            duration_ms,
            format!("read after ClientHello failed: {}", explain_io_error(&e)),
        )),
        Err(_) => evidence(ProbeResult::failure(
            duration_ms,
            format!(
                "TCP connected but no ServerHello arrived within {} ms; a large-packet \
                 black hole (PMTU) or a filtering middlebox both look like this",
                ctx.timeout.as_millis()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_a_well_formed_record() {
        let hello = client_hello("example.com");
        assert_eq!(hello[0], 0x16, "content type must be handshake");
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5, "record length must match");
        assert_eq!(hello[5], 0x01, "handshake type must be ClientHello");
        let handshake_len =
            ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | hello[8] as usize;
        assert_eq!(handshake_len, hello.len() - 9);
    }

    #[test]
    fn sni_is_included_for_hostnames_and_omitted_for_literals() {
        let with_name = client_hello("example.com");
        assert!(
            with_name.windows(11).any(|w| w == b"example.com"),
            "SNI should carry the hostname"
        );
        // An IP literal is not a legal SNI value, so it must be left out.
        let with_literal = client_hello("1.1.1.1");
        assert!(!with_literal.windows(7).any(|w| w == b"1.1.1.1"));
    }

    #[test]
    fn recognises_a_server_hello() {
        let reply = [0x16, 0x03, 0x03, 0x00, 0x2a, 0x02, 0x00];
        assert_eq!(classify_reply(&reply), HelloReply::ServerHello);
    }

    #[test]
    fn recognises_an_alert() {
        let reply = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40];
        assert_eq!(
            classify_reply(&reply),
            HelloReply::Alert {
                level: 2,
                description: 40
            }
        );
        assert_eq!(alert_name(40), "handshake_failure");
    }

    #[test]
    fn plain_http_response_is_not_tls() {
        assert_eq!(classify_reply(b"HTTP/1.1 400"), HelloReply::NotTls);
    }
}
