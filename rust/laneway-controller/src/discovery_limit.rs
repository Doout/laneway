//! Fixed one-minute discovery windows matching Go's auth-state limiter.
//! Every request uses the same logical username, so its 300-attempt cap
//! also bounds the global count, even when a source has already been denied.
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};
const WINDOW: Duration = Duration::from_secs(60);
#[derive(Default)]
pub struct Limiter {
    shared: Option<(Instant, u32)>,
    sources: HashMap<IpAddr, (Instant, u32)>,
}
impl Limiter {
    pub fn check(&mut self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        let ip = match ip.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & (!0_u128 << 64)).into()),
            other => other,
        };
        self.sources
            .retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
        let shared = self.shared.get_or_insert((now, 0));
        if now.duration_since(shared.0) >= WINDOW {
            *shared = (now, 0);
        }
        let remaining = |start: Instant| {
            (WINDOW - now.duration_since(start))
                .as_nanos()
                .div_ceil(1_000_000_000)
                .max(1) as u64
        };
        if self.sources.len() >= 4096 && !self.sources.contains_key(&ip) {
            return Err(remaining(shared.0));
        }
        let source = self.sources.entry(ip).or_insert((now, 0));
        shared.1 = shared.1.saturating_add(1);
        source.1 = source.1.saturating_add(1);
        let wait = (if shared.1 > 300 {
            remaining(shared.0)
        } else {
            0
        })
        .max(if source.1 > 30 {
            remaining(source.0)
        } else {
            0
        });
        if wait == 0 { Ok(()) } else { Err(wait) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_global_and_window_reset() {
        let mut limits = Limiter::default();
        let now = Instant::now();
        for _ in 0..30 {
            assert!(limits.check("::1".parse().unwrap(), now).is_ok())
        }
        assert_eq!(limits.check("::2".parse().unwrap(), now), Err(60));
        for n in 0..269 {
            assert!(limits.check(IpAddr::V4((n + 12345u32).into()), now).is_ok())
        }
        assert_eq!(
            limits.check(
                "127.0.0.1".parse().unwrap(),
                now + Duration::from_millis(100)
            ),
            Err(60)
        );
        assert!(limits.check("::1".parse().unwrap(), now + WINDOW).is_ok());
    }
}
