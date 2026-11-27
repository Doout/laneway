//! Bounded UDP datapath benchmark for the integration harness.
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::json;
use tokio::{net::UdpSocket, task::JoinSet, time};

#[derive(Args)]
pub(super) struct Options {
    #[arg(long)]
    target: SocketAddr,
    #[arg(long, default_value = "kernel-path")]
    scenario: String,
    #[arg(long, default_value = "udp-echo-unspecified-path")]
    scope: String,
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
    duration: Duration,
    #[arg(long, default_value_t = 1200, value_parser = clap::value_parser!(u32).range(16..=60000))]
    size: u32,
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    pps: u32,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=100))]
    flows: u32,
}

const MAX_SAMPLES: u64 = 1_000_000;

pub(super) async fn run(options: Options) -> Result<()> {
    let interval = Duration::from_secs(1) / options.pps;
    ensure!(
        (Duration::from_millis(10)..=Duration::from_secs(60)).contains(&options.duration)
            && options.duration > interval,
        "UDP benchmark duration must be 10ms–60s and exceed one packet interval"
    );
    for label in [&options.scenario, &options.scope] {
        ensure!(
            (1..=128).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')),
            "UDP benchmark requires bounded scenario and scope labels"
        );
    }

    let bound = u64::try_from(options.duration.as_nanos().div_ceil(interval.as_nanos()))?;
    let stride = bound.div_ceil(MAX_SAMPLES);
    let flows = u64::from(options.flows);
    let size = usize::try_from(options.size)?;
    let any = if options.target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let mut sockets = Vec::with_capacity(options.flows as usize);
    for _ in 0..flows {
        let socket = UdpSocket::bind(any).await?;
        socket.connect(options.target).await?;
        sockets.push(Arc::new(socket));
    }

    let cpu_start = cpu_time();
    let started = Instant::now();
    let deadline = started + options.duration;
    let drain = deadline + Duration::from_millis(250);
    let mut receivers = JoinSet::new();
    for (flow, socket) in sockets.iter().enumerate() {
        receivers.spawn(receive(
            Arc::clone(socket),
            flow as u64,
            flows,
            size,
            bound,
            stride,
            started,
            drain,
        ));
    }

    let tick = interval.max(Duration::from_millis(1));
    let first = time::Instant::from_std(started + tick);
    let mut ticker = time::interval_at(first, tick);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let per_tick = u64::try_from(tick.as_nanos().div_ceil(interval.as_nanos()))?;
    let mut output = vec![0; size];
    let mut generated = 0;
    let mut sent = 0;
    while generated < bound {
        ticker.tick().await;
        let due = u64::try_from(started.elapsed().as_nanos() / interval.as_nanos())?
            .min(bound)
            .min(generated + per_tick);
        while generated < due && Instant::now() < deadline {
            let socket = &sockets[(generated % flows) as usize];
            generated += 1;
            output[..8].copy_from_slice(&generated.to_be_bytes());
            output[8..16].copy_from_slice(&elapsed_ns(started)?.to_be_bytes());
            if time::timeout_at(time::Instant::from_std(deadline), socket.send(&output))
                .await
                .is_ok_and(|result| result.is_ok_and(|count| count == size))
            {
                sent += 1;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    let measured = started.elapsed();
    let mut samples = Vec::new();
    let mut received = 0;
    let mut bad = 0;
    while let Some(result) = receivers.join_next().await {
        let part = result??;
        received += part.received;
        bad += part.bad;
        samples.extend(part.samples);
    }
    let resources = started.elapsed();
    ensure!(
        sent > 0 && received > 0 && received <= sent && !samples.is_empty(),
        "UDP benchmark did not complete a valid measured packet exchange"
    );
    samples.sort_unstable();
    let quantile = |percent: usize| samples[(samples.len() * percent).div_ceil(100) - 1] / 1_000;
    let drops = sent - received;
    let bytes = received * u64::from(options.size);
    let cpu = cpu_time().saturating_sub(cpu_start);
    println!(
        "{}",
        json!({
            "schema": "laneway-kernel-datapath-benchmark-v1",
            "scenario": options.scenario, "scope": options.scope, "flows": flows, "packet_size": size,
            "duration_ms": measured.as_millis() as u64, "resource_duration_ms": resources.as_millis() as u64,
            "resource_scope": if cfg!(target_os = "linux") { "process-clock+procfs-rss+rust" } else { "rust" },
            "generated": generated, "sent": sent, "send_errors": generated - sent, "received": received, "bytes": bytes,
            "drops": drops, "bad": bad, "loss_percent": 100.0 * drops as f64 / sent as f64,
            "pps": received as f64 / measured.as_secs_f64(), "gbps": bytes as f64 * 8e-9 / measured.as_secs_f64(),
            "p50_us": quantile(50), "p95_us": quantile(95), "p99_us": quantile(99), "latency_samples": samples.len(),
            "cpu_percent": 100.0 * cpu.as_secs_f64() / resources.as_secs_f64(), "rss_bytes": rss(),
            "allocations": 0, "gc_count": 0, "gc_pause_ns": 0
        })
    );
    Ok(())
}

fn elapsed_ns(started: Instant) -> Result<u64> {
    u64::try_from(started.elapsed().as_nanos()).context("benchmark clock exceeds its valid range")
}

#[derive(Default)]
struct Received {
    received: u64,
    bad: u64,
    samples: Vec<u64>,
}

#[allow(clippy::too_many_arguments)]
async fn receive(
    socket: Arc<UdpSocket>,
    flow: u64,
    flows: u64,
    size: usize,
    bound: u64,
    stride: u64,
    started: Instant,
    drain: Instant,
) -> Result<Received> {
    let mut outcome = Received::default();
    let mut seen = vec![0u64; usize::try_from(bound.div_ceil(flows).div_ceil(64))?];
    let mut buffer = vec![0u8; size + 1];
    let deadline = time::Instant::from_std(drain);
    while Instant::now() < drain {
        let Ok(read) = time::timeout_at(deadline, socket.recv(&mut buffer)).await else {
            break;
        };
        let length = match read {
            Ok(length) => length,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => continue,
            Err(error) => return Err(error).context("receive UDP benchmark reply"),
        };
        let sequence = u64::from_be_bytes(buffer[..8].try_into()?);
        let sent_at = u64::from_be_bytes(buffer[8..16].try_into()?);
        let now = elapsed_ns(started)?;
        if length != size
            || !(1..=bound).contains(&sequence)
            || (sequence - 1) % flows != flow
            || sent_at == 0
            || sent_at > now
        {
            outcome.bad += 1;
            continue;
        }
        let index = (sequence - 1) / flows;
        let word = &mut seen[(index / 64) as usize];
        let mask = 1u64 << (index % 64);
        if *word & mask != 0 {
            outcome.bad += 1;
            continue;
        }
        *word |= mask;
        outcome.received += 1;
        if (sequence - 1).is_multiple_of(stride) {
            outcome.samples.push(now - sent_at);
        }
    }
    Ok(outcome)
}

#[cfg(target_os = "linux")]
fn cpu_time() -> Duration {
    let mut stamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime fills the writable timestamp on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut stamp) } != 0 {
        return Duration::ZERO;
    }
    Duration::new(stamp.tv_sec as u64, stamp.tv_nsec as u32)
}

#[cfg(target_os = "linux")]
fn rss() -> u64 {
    // SAFETY: sysconf takes only a constant and reads this process's page size.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|value| value.split_whitespace().nth(1)?.parse::<u64>().ok())
        .zip(u64::try_from(page_size).ok())
        .map_or(0, |(pages, bytes)| pages.saturating_mul(bytes))
}

#[cfg(not(target_os = "linux"))]
fn cpu_time() -> Duration {
    Duration::ZERO
}

#[cfg(not(target_os = "linux"))]
fn rss() -> u64 {
    0
}
