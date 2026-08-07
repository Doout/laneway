use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use crossbeam_queue::ArrayQueue;

use anyhow::{Result, anyhow};
use bytes::Bytes;

#[derive(Clone)]
pub(crate) struct PacketPool {
    buffers: Arc<ArrayQueue<Vec<u8>>>,
    capacity: usize,
}

impl PacketPool {
    pub(crate) fn prewarmed(count: usize, capacity: usize) -> Self {
        let buffers = Arc::new(ArrayQueue::new(count));
        for _ in 0..count {
            buffers
                .push(Vec::with_capacity(capacity))
                .expect("new packet pool has room");
        }
        Self { buffers, capacity }
    }

    pub(crate) fn take(&self) -> (PooledPacket, bool) {
        let (mut buffer, miss) = self.buffers.pop().map_or_else(
            || (Vec::with_capacity(self.capacity), true),
            |value| (value, false),
        );
        buffer.clear();
        (
            PooledPacket {
                buffer: Some(buffer),
                pool: Arc::clone(&self.buffers),
            },
            miss,
        )
    }
}

pub(crate) struct PooledPacket {
    buffer: Option<Vec<u8>>,
    pool: Arc<ArrayQueue<Vec<u8>>>,
}

impl AsRef<[u8]> for PooledPacket {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl Deref for PooledPacket {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().expect("packet buffer present")
    }
}

impl DerefMut for PooledPacket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().expect("packet buffer present")
    }
}

impl Drop for PooledPacket {
    fn drop(&mut self) {
        let Some(mut buffer) = self.buffer.take() else {
            return;
        };
        buffer.clear();
        let _ = self.pool.push(buffer);
    }
}

pub(crate) enum PacketBuffer {
    Bytes(Bytes),
    Pooled(PooledPacket),
}

impl PacketBuffer {
    pub(crate) fn retag(self, prefix: &[u8; 5]) -> Result<Bytes> {
        match self {
            Self::Bytes(bytes) => {
                let mut bytes = bytes
                    .try_into_mut()
                    .map_err(|_| anyhow!("packet buffer unexpectedly shared"))?;
                bytes[..5].copy_from_slice(prefix);
                Ok(bytes.freeze())
            }
            Self::Pooled(mut packet) => {
                packet[..5].copy_from_slice(prefix);
                Ok(Bytes::from_owner(packet))
            }
        }
    }
}

impl AsRef<[u8]> for PacketBuffer {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes.as_ref(),
            Self::Pooled(packet) => packet.as_ref(),
        }
    }
}

impl From<Bytes> for PacketBuffer {
    fn from(value: Bytes) -> Self {
        Self::Bytes(value)
    }
}

impl From<PooledPacket> for PacketBuffer {
    fn from(value: PooledPacket) -> Self {
        Self::Pooled(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_owner_returns_the_same_prewarmed_storage() {
        let pool = PacketPool::prewarmed(1, 1285);
        let (mut packet, miss) = pool.take();
        assert!(!miss);
        packet.extend_from_slice(&[1, 2, 3]);
        let pointer = packet.as_ptr();
        let bytes = bytes::Bytes::from_owner(packet);
        assert_eq!(&bytes[..], &[1, 2, 3]);
        drop(bytes);

        let (packet, miss) = pool.take();
        assert!(!miss);
        assert_eq!(packet.as_ptr(), pointer);
    }

    #[test]
    fn exhaustion_is_bounded_and_reported_as_a_miss() {
        let pool = PacketPool::prewarmed(1, 1285);
        let (_held, miss) = pool.take();
        assert!(!miss);
        let (_fallback, miss) = pool.take();
        assert!(miss);
    }
}
