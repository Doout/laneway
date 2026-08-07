use anyhow::{Context, Result, ensure};
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const MAX_CONTROL_PAYLOAD: usize = 1 << 20;

pub(crate) async fn read_message<R, M>(reader: &mut R, maximum: usize) -> Result<M>
where
    R: AsyncRead + Unpin,
    M: Message + Default,
{
    let length = reader.read_u32().await.context("read frame length")? as usize;
    ensure!(length > 0 && length <= maximum, "invalid frame length");
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("read frame payload")?;
    M::decode(payload.as_slice()).context("decode protobuf frame")
}

pub(crate) async fn write_message<W, M>(writer: &mut W, message: &M, maximum: usize) -> Result<()>
where
    W: AsyncWrite + Unpin,
    M: Message,
{
    let payload = encode_message(message, maximum)?;
    let length = payload.len();
    ensure!(
        length > 0 && length <= maximum && length <= u32::MAX as usize,
        "frame too large"
    );
    writer.write_u32(length as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) fn encode_message<M: Message>(message: &M, maximum: usize) -> Result<Vec<u8>> {
    let length = message.encoded_len();
    ensure!(
        length > 0 && length <= maximum && length <= u32::MAX as usize,
        "frame too large"
    );
    let mut payload = Vec::with_capacity(length);
    message.encode(&mut payload)?;
    Ok(payload)
}

pub(crate) fn decode_message<M: Message + Default>(payload: &[u8]) -> Result<M> {
    M::decode(payload).context("decode protobuf record")
}

pub(crate) fn next_sequence(sequence: &mut u64) -> Result<u64> {
    let current = *sequence;
    ensure!(current != 0, "sequence exhausted");
    *sequence = current.checked_add(1).context("sequence exhausted")?;
    Ok(current)
}

#[cfg(test)]
mod tests {
    use laneway_protocol::v1::ControlEnvelope;

    use super::*;

    #[tokio::test]
    async fn bounded_frame_round_trip() {
        let envelope = ControlEnvelope {
            schema_version: 1,
            sequence: 1,
            body: None,
        };
        let (mut left, mut right) = tokio::io::duplex(128);
        let writer = tokio::spawn(async move { write_message(&mut left, &envelope, 128).await });
        let decoded: ControlEnvelope = read_message(&mut right, 128).await.unwrap();
        writer.await.unwrap().unwrap();
        assert_eq!(decoded.sequence, 1);
    }
}
