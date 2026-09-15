//! Length-delimited protobuf framing over a Unix stream.
//!
//! Each frame is a protobuf varint byte count followed by that many bytes. This
//! is exactly what `prost::Message::encode_length_delimited` writes and what
//! Java's `parseDelimitedFrom` reads, so both sides get framing for free
//! instead of inventing a header that then has to be kept in sync.

use anyhow::{Context, Result, bail};
use bytes::BytesMut;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Refuse absurd frames rather than trying to allocate them. The largest thing
/// a client legitimately sends is a Diagnose request carrying the framework
/// state, which is a few hundred kilobytes at most.
pub const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;

/// Read one length-delimited message. Returns `Ok(None)` on a clean EOF at a
/// frame boundary, which is how a client signals it is done.
pub async fn read_frame<M, R>(reader: &mut R) -> Result<Option<M>>
where
    M: Message + Default,
    R: AsyncReadExt + Unpin,
{
    let len = match read_varint(reader).await? {
        Some(len) => len,
        None => return Ok(None),
    };
    if len > MAX_FRAME_BYTES as u64 {
        bail!("frame of {len} bytes exceeds the {MAX_FRAME_BYTES} byte limit");
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .await
        .context("short read on frame body")?;
    let msg = M::decode(buf.as_slice()).context("malformed protobuf frame")?;
    Ok(Some(msg))
}

/// Write one length-delimited message and flush it. Flushing per frame keeps
/// streamed events from sitting in the buffer while the UI waits for them.
pub async fn write_frame<M, W>(writer: &mut W, msg: &M) -> Result<()>
where
    M: Message,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = BytesMut::with_capacity(msg.encoded_len() + 8);
    msg.encode_length_delimited(&mut buf)
        .context("failed to encode frame")?;
    writer
        .write_all(&buf)
        .await
        .context("failed to write frame")?;
    writer.flush().await.context("failed to flush frame")?;
    Ok(())
}

/// Read a protobuf varint one byte at a time. Frames are rare enough (and the
/// varint short enough) that this is not worth buffering machinery.
async fn read_varint<R>(reader: &mut R) -> Result<Option<u64>>
where
    R: AsyncReadExt + Unpin,
{
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut byte = [0u8; 1];

    loop {
        match reader.read(&mut byte).await {
            Ok(0) => {
                if shift == 0 {
                    // Clean EOF between frames.
                    return Ok(None);
                }
                bail!("EOF in the middle of a frame length varint");
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && shift == 0 => {
                return Ok(None);
            }
            Err(e) => return Err(e).context("read error on frame length"),
        }

        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(Some(value));
        }
        shift += 7;
        if shift >= 64 {
            bail!("frame length varint is too long");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto;

    #[tokio::test]
    async fn roundtrips_a_frame() {
        let msg = proto::HelloRequest {
            protocol_version: 1,
            client_name: "test".into(),
            client_version: "0.1".into(),
        };
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &msg).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded: proto::HelloRequest = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(decoded.client_name, "test");
    }

    #[tokio::test]
    async fn clean_eof_is_not_an_error() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let decoded: Option<proto::HelloRequest> = read_frame(&mut cursor).await.unwrap();
        assert!(decoded.is_none());
    }

    #[tokio::test]
    async fn reads_several_frames_back_to_back() {
        let mut buf: Vec<u8> = Vec::new();
        for i in 0..3u32 {
            let msg = proto::HelloRequest {
                protocol_version: i,
                ..Default::default()
            };
            write_frame(&mut buf, &msg).await.unwrap();
        }
        let mut cursor = std::io::Cursor::new(buf);
        for i in 0..3u32 {
            let decoded: proto::HelloRequest = read_frame(&mut cursor).await.unwrap().unwrap();
            assert_eq!(decoded.protocol_version, i);
        }
        assert!(
            read_frame::<proto::HelloRequest, _>(&mut cursor)
                .await
                .unwrap()
                .is_none()
        );
    }
}
