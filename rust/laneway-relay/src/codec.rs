use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::v1::{ControlEnvelope, RelayEnvelope};
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const SCHEMA_VERSION: u32 = 1;

pub(crate) async fn read_message<R, M>(reader: &mut R, maximum: usize) -> Result<M>
where
    R: AsyncRead + Unpin,
    M: Message + Default,
{
    let length = reader
        .read_u32()
        .await
        .context("read control frame length")? as usize;
    ensure!(
        length > 0 && length <= maximum,
        "control frame length {length} is invalid"
    );
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("read control frame payload")?;
    M::decode(payload.as_slice()).context("decode control protobuf")
}

pub(crate) async fn write_message<W, M>(writer: &mut W, message: &M, maximum: usize) -> Result<()>
where
    W: AsyncWrite + Unpin,
    M: Message,
{
    let payload = encode_message(message, maximum)?;
    let length = payload.len();
    writer
        .write_u32(length as u32)
        .await
        .context("write control frame length")?;
    writer
        .write_all(&payload)
        .await
        .context("write control frame payload")?;
    writer.flush().await.context("flush control frame")
}

pub(crate) fn encode_message<M: Message>(message: &M, maximum: usize) -> Result<Vec<u8>> {
    let length = message.encoded_len();
    ensure!(
        length > 0 && length <= maximum && length <= u32::MAX as usize,
        "control frame is too large"
    );
    let mut payload = Vec::with_capacity(length);
    message
        .encode(&mut payload)
        .context("encode control protobuf")?;
    Ok(payload)
}

pub(crate) struct ControlReader {
    next: u64,
}

impl ControlReader {
    pub(crate) fn new() -> Self {
        Self { next: 1 }
    }

    pub(crate) async fn read<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        maximum: usize,
    ) -> Result<ControlEnvelope> {
        let envelope: ControlEnvelope = read_message(reader, maximum).await?;
        self.validate(envelope)
    }

    pub(crate) fn decode(&mut self, payload: &[u8]) -> Result<ControlEnvelope> {
        let envelope = ControlEnvelope::decode(payload).context("decode control protobuf")?;
        self.validate(envelope)
    }

    fn validate(&mut self, envelope: ControlEnvelope) -> Result<ControlEnvelope> {
        ensure!(
            envelope.schema_version == SCHEMA_VERSION,
            "invalid control schema version"
        );
        ensure!(
            envelope.sequence == self.next,
            "unexpected control sequence"
        );
        ensure!(envelope.body.is_some(), "control envelope has no body");
        self.next = self
            .next
            .checked_add(1)
            .context("control sequence exhausted")?;
        Ok(envelope)
    }
}

pub(crate) async fn write_control<W: AsyncWrite + Unpin>(
    writer: &mut W,
    sequence: u64,
    body: laneway_protocol::v1::control_envelope::Body,
    maximum: usize,
) -> Result<()> {
    if sequence == 0 {
        bail!("control sequence is zero");
    }
    write_message(
        writer,
        &ControlEnvelope {
            schema_version: SCHEMA_VERSION,
            sequence,
            body: Some(body),
        },
        maximum,
    )
    .await
}

pub(crate) struct RelayReader {
    next: u64,
}

impl RelayReader {
    pub(crate) fn new() -> Self {
        Self { next: 1 }
    }

    pub(crate) async fn read<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        maximum: usize,
    ) -> Result<RelayEnvelope> {
        let envelope: RelayEnvelope = read_message(reader, maximum).await?;
        self.validate(envelope)
    }

    pub(crate) fn decode(&mut self, payload: &[u8]) -> Result<RelayEnvelope> {
        let envelope = RelayEnvelope::decode(payload).context("decode relay protobuf")?;
        self.validate(envelope)
    }

    fn validate(&mut self, envelope: RelayEnvelope) -> Result<RelayEnvelope> {
        ensure!(
            envelope.schema_version == SCHEMA_VERSION,
            "invalid relay schema version"
        );
        ensure!(envelope.sequence == self.next, "unexpected relay sequence");
        ensure!(envelope.body.is_some(), "relay envelope has no body");
        self.next = self
            .next
            .checked_add(1)
            .context("relay sequence exhausted")?;
        Ok(envelope)
    }
}

pub(crate) async fn write_relay<W: AsyncWrite + Unpin>(
    writer: &mut W,
    sequence: u64,
    body: laneway_protocol::v1::relay_envelope::Body,
    maximum: usize,
) -> Result<()> {
    if sequence == 0 {
        bail!("relay sequence is zero");
    }
    write_message(
        writer,
        &RelayEnvelope {
            schema_version: SCHEMA_VERSION,
            sequence,
            body: Some(body),
        },
        maximum,
    )
    .await
}

#[cfg(test)]
mod tests {
    use laneway_protocol::v1::{Hello, control_envelope};

    use super::*;

    #[tokio::test]
    async fn round_trip_and_sequence_validation() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let writing = tokio::spawn(async move {
            write_control(
                &mut writer,
                1,
                control_envelope::Body::Hello(Hello {
                    network_id: vec![1; 16],
                    node_id: vec![2; 16],
                    boot_id: vec![3; 16],
                    protocol_major: 1,
                    protocol_minor: 0,
                    capabilities: 3,
                }),
                1024,
            )
            .await
        });
        let envelope = ControlReader::new().read(&mut reader, 1024).await.unwrap();
        assert!(matches!(
            envelope.body,
            Some(control_envelope::Body::Hello(_))
        ));
        writing.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_zero_and_oversized_frames() {
        for length in [0_u32, 17] {
            let (mut writer, mut reader) = tokio::io::duplex(64);
            writer.write_u32(length).await.unwrap();
            drop(writer);
            assert!(
                read_message::<_, ControlEnvelope>(&mut reader, 16)
                    .await
                    .is_err()
            );
        }
    }
}
