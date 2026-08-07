use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use crossbeam_queue::ArrayQueue;

/// Bounded lock-free pool for packet allocations handed through QUIC.
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

    pub(crate) fn copy(&self, packet: &[u8]) -> (PooledPacket, bool) {
        let (mut pooled, miss) = self.take();
        pooled.extend_from_slice(packet);
        (pooled, miss)
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
                pool: Some(Arc::clone(&self.buffers)),
            },
            miss,
        )
    }
}

/// Packet storage returned to its originating pool when Quinn releases it.
#[derive(Debug)]
pub(crate) struct PooledPacket {
    buffer: Option<Vec<u8>>,
    pool: Option<Arc<ArrayQueue<Vec<u8>>>>,
}

impl PooledPacket {
    #[cfg(test)]
    pub(crate) fn unpooled(buffer: Vec<u8>) -> Self {
        Self {
            buffer: Some(buffer),
            pool: None,
        }
    }
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
        if let Some(pool) = &self.pool {
            let _ = pool.push(buffer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warmed_buffers_return_without_a_miss() {
        let pool = PacketPool::prewarmed(1, 1285);
        let (packet, miss) = pool.copy(&[1, 2, 3]);
        assert!(!miss);
        assert_eq!(packet.as_slice(), &[1, 2, 3]);
        drop(packet);
        let (_, miss) = pool.copy(&[4]);
        assert!(!miss);
    }

    #[test]
    fn bytes_owner_returns_warmed_receive_buffer() {
        let pool = PacketPool::prewarmed(1, 1285);
        let (mut packet, miss) = pool.take();
        assert!(!miss);
        packet.extend_from_slice(&[1, 2, 3]);
        let bytes = bytes::Bytes::from_owner(packet);
        assert_eq!(&bytes[..], &[1, 2, 3]);
        drop(bytes);
        let (_, miss) = pool.take();
        assert!(!miss);
    }
}
