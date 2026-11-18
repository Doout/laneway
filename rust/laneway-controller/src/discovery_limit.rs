//! Per-process fixed windows. Track normalized names by keyed hash, not text.
use std::{
    collections::HashMap,
    hash::{BuildHasher, RandomState},
    net::IpAddr,
    time::{Duration, Instant},
};
const WINDOW: Duration = Duration::from_secs(60);
type Window = (Instant, u32);
pub struct Limiter {
    limits: (u32, u32, u32),
    global: Option<Window>,
    sources: HashMap<IpAddr, Window>,
    names: HashMap<u64, Window>,
    key: RandomState,
}
impl Default for Limiter {
    fn default() -> Self {
        Self::new((300, 30, 300))
    }
}
impl Limiter {
    fn new(limits: (u32, u32, u32)) -> Self {
        Self {
            limits,
            global: None,
            sources: HashMap::new(),
            names: HashMap::new(),
            key: RandomState::new(),
        }
    }
    pub fn login() -> Self {
        Self::new((60, 10, 5))
    }
    pub fn check(&mut self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        self.attempt(ip, "auth-state", now)
    }
    pub fn attempt(&mut self, ip: IpAddr, name: &str, now: Instant) -> Result<(), u64> {
        let name = name.trim();
        let normalized = if name.is_empty() || name.len() > 64 {
            "invalid".to_owned()
        } else {
            name.to_lowercase()
        };
        let key = self.key.hash_one(&normalized);
        let ip = match ip.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & (!0_u128 << 64)).into()),
            other => other,
        };
        self.sources
            .retain(|_, (t, _)| now.duration_since(*t) < WINDOW);
        self.names
            .retain(|_, (t, _)| now.duration_since(*t) < WINDOW);
        let global = self.global.get_or_insert((now, 0));
        if now.duration_since(global.0) >= WINDOW {
            *global = (now, 0)
        }
        let remaining = |t: Instant| {
            (WINDOW - now.duration_since(t))
                .as_nanos()
                .div_ceil(1_000_000_000)
                .max(1) as u64
        };
        if (self.sources.len() >= 4096 && !self.sources.contains_key(&ip))
            || (self.names.len() >= 4096 && !self.names.contains_key(&key))
        {
            return Err(remaining(global.0));
        }
        let source = self.sources.entry(ip).or_insert((now, 0));
        let user = self.names.entry(key).or_insert((now, 0));
        source.1 = source.1.saturating_add(1);
        user.1 = user.1.saturating_add(1);
        let wait = (if source.1 > self.limits.1 {
            remaining(source.0)
        } else {
            0
        })
        .max(if user.1 > self.limits.2 {
            remaining(user.0)
        } else {
            0
        });
        if wait > 0 {
            return Err(wait);
        }
        if global.1 >= self.limits.0 {
            return Err(remaining(global.0));
        }
        global.1 += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn login_admission_combines_name_source_and_global_windows() {
        let now = Instant::now();
        let mut by_name = Limiter::login();
        for i in 1..=5 {
            assert!(
                by_name
                    .attempt(IpAddr::V4(i.into()), " Web-Owner ", now)
                    .is_ok()
            );
        }
        assert_eq!(
            by_name.attempt("127.0.0.1".parse().unwrap(), "web-owner", now),
            Err(60)
        );
        let mut by_source = Limiter::login();
        for i in 0..10 {
            assert!(
                by_source
                    .attempt("::1".parse().unwrap(), &format!("name-{i}"), now)
                    .is_ok()
            );
        }
        assert_eq!(
            by_source.attempt("::2".parse().unwrap(), "new-name", now),
            Err(60)
        );
        let mut global = Limiter::login();
        for i in 1..=60 {
            assert!(
                global
                    .attempt(IpAddr::V4(i.into()), &format!("name-{i}"), now)
                    .is_ok()
            );
        }
        assert_eq!(
            global.attempt("127.0.0.1".parse().unwrap(), "new-name", now),
            Err(60)
        );
        assert!(
            global
                .attempt("127.0.0.1".parse().unwrap(), "new-name", now + WINDOW)
                .is_ok()
        );
    }
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
