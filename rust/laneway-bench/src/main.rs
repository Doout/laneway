use std::{
    alloc::{GlobalAlloc, Layout, System},
    env, fs,
    hint::spin_loop,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use crossbeam_queue::ArrayQueue;
use ipnet::IpNet;
use laneway_protocol::{Id, PacketHeader};
use laneway_relay::benchmark::{ForwardingHarness, validate_and_retag};
use lanewayd_rs::{RouteConfig, RouteKind, RoutingTable, benchmark::route_and_frame};
use serde_json::json;

const MAX_PACKET: usize = 9000;
const QUEUE_DEPTH: usize = 256;
const MAX_LATENCY_SAMPLES: usize = 1_000_000;

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: delegated unchanged to the process system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: pointer/layout came from the matching allocation above.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: delegated unchanged to the process system allocator.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Node,
    Relay,
    RelayForward,
}

struct Options {
    mode: Mode,
    flows: usize,
    packet_size: usize,
    duration: Duration,
}

struct Frame {
    sent: Instant,
    flow: usize,
    length: usize,
    payload_length: usize,
    bytes: [u8; MAX_PACKET + 5],
}

fn main() -> Result<()> {
    let options = options()?;
    let queue = Arc::new(ArrayQueue::<Frame>::new(QUEUE_DEPTH));
    let stop = Arc::new(AtomicBool::new(false));
    let delivered = Arc::new(AtomicU64::new(0));
    let delivered_bytes = Arc::new(AtomicU64::new(0));
    let queue_max = Arc::new(AtomicUsize::new(0));
    let routes = node_routes(options.flows)?;
    let relay_forwarder = (options.mode == Mode::RelayForward)
        .then(|| ForwardingHarness::new(options.flows, QUEUE_DEPTH))
        .transpose()?;

    // Allocate all reporting and queue storage before the measured interval.
    let consumer_queue = Arc::clone(&queue);
    let consumer_stop = Arc::clone(&stop);
    let consumer_delivered = Arc::clone(&delivered);
    let consumer_bytes = Arc::clone(&delivered_bytes);
    let mode = options.mode;
    let consumer = thread::spawn(move || {
        let mut relay_forwarder = relay_forwarder;
        let mut samples = Vec::with_capacity(MAX_LATENCY_SAMPLES);
        let mut framed = [0_u8; MAX_PACKET + 5];
        while !consumer_stop.load(Ordering::Acquire) || !consumer_queue.is_empty() {
            let Some(mut frame) = consumer_queue.pop() else {
                spin_loop();
                continue;
            };
            let valid = match mode {
                Mode::Node => node_dataplane(&routes, &frame, &mut framed),
                Mode::Relay => relay_dataplane(&mut frame),
                Mode::RelayForward => relay_forwarder
                    .as_mut()
                    .is_some_and(|forwarder| forwarder.forward(&frame.bytes[..frame.length])),
            };
            if valid {
                consumer_delivered.fetch_add(1, Ordering::Relaxed);
                consumer_bytes.fetch_add(frame.payload_length as u64, Ordering::Relaxed);
                if samples.len() < MAX_LATENCY_SAMPLES {
                    samples.push(frame.sent.elapsed().as_nanos() as u64);
                }
            }
        }
        samples
    });

    let start_cpu = process_ticks()?;
    let start_allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let started = Instant::now();
    let deadline = started + options.duration;
    let mut attempted = 0_u64;
    let mut dropped = 0_u64;
    let mut sequence = 0_u64;
    while Instant::now() < deadline {
        let flow = sequence as usize % options.flows;
        let mut frame = Frame {
            sent: Instant::now(),
            flow,
            length: options.packet_size
                + usize::from(matches!(options.mode, Mode::Relay | Mode::RelayForward)) * 5,
            payload_length: options.packet_size,
            bytes: [0; MAX_PACKET + 5],
        };
        encode_packet(&mut frame, sequence, options.mode);
        attempted += 1;
        sequence = sequence.wrapping_add(1);
        if queue.push(frame).is_err() {
            dropped += 1;
        } else {
            queue_max.fetch_max(queue.len(), Ordering::Relaxed);
        }
    }
    stop.store(true, Ordering::Release);
    let mut samples = consumer
        .join()
        .map_err(|_| anyhow::anyhow!("consumer panicked"))?;
    let elapsed = started.elapsed();
    let allocations = ALLOCATIONS
        .load(Ordering::Relaxed)
        .saturating_sub(start_allocations);
    let cpu_ticks = process_ticks()?.saturating_sub(start_cpu);
    let packets = delivered.load(Ordering::Relaxed);
    let bytes = delivered_bytes.load(Ordering::Relaxed);
    samples.sort_unstable();

    let seconds = elapsed.as_secs_f64();
    let percentile = |value: f64| -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        let index = ((samples.len() - 1) as f64 * value).round() as usize;
        samples[index] as f64 / 1_000.0
    };
    let mode = match options.mode {
        Mode::Node => "node",
        Mode::Relay => "relay",
        Mode::RelayForward => "relay-forward",
    };
    println!(
        "{}",
        serde_json::to_string(&json!({
            "mode": mode,
            "flows": options.flows,
            "packet_size": options.packet_size,
            "duration_seconds": seconds,
            "packets": packets,
            "bytes": bytes,
            "pps": packets as f64 / seconds,
            "gbps": bytes as f64 * 8.0 / seconds / 1_000_000_000.0,
            "p50_us": percentile(0.50),
            "p95_us": percentile(0.95),
            "p99_us": percentile(0.99),
            "drops": dropped,
            "loss_percent": if attempted == 0 { 0.0 } else { dropped as f64 * 100.0 / attempted as f64 },
            "cpu_percent": cpu_ticks as f64 / 100.0 / seconds * 100.0,
            "rss_bytes": rss_bytes()?,
            "allocations": allocations,
            "allocations_per_packet": if packets == 0 { 0.0 } else { allocations as f64 / packets as f64 },
            "queue_depth_max": queue_max.load(Ordering::Relaxed),
        }))?
    );
    Ok(())
}

fn options() -> Result<Options> {
    let mut mode = None;
    let mut flows = None;
    let mut packet_size = None;
    let mut duration = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--json" {
            continue;
        }
        let value = arguments
            .next()
            .with_context(|| format!("{argument} requires a value"))?;
        match argument.as_str() {
            "--mode" => {
                mode = Some(match value.as_str() {
                    "node" => Mode::Node,
                    "relay" => Mode::Relay,
                    "relay-forward" => Mode::RelayForward,
                    _ => bail!("--mode must be node, relay, or relay-forward"),
                })
            }
            "--flows" => flows = Some(value.parse::<usize>().context("invalid --flows")?),
            "--packet-size" => {
                packet_size = Some(value.parse::<usize>().context("invalid --packet-size")?)
            }
            "--duration-secs" => {
                duration = Some(Duration::from_secs_f64(
                    value.parse::<f64>().context("invalid --duration-secs")?,
                ))
            }
            _ => bail!("unknown argument {argument}"),
        }
    }
    let flows = flows.context("--flows is required")?;
    let packet_size = packet_size.context("--packet-size is required")?;
    let duration = duration.context("--duration-secs is required")?;
    ensure!(
        matches!(flows, 1 | 10 | 100),
        "--flows must be 1, 10, or 100"
    );
    ensure!(
        (64..=MAX_PACKET).contains(&packet_size),
        "packet size is out of range"
    );
    ensure!(
        mode != Some(Mode::RelayForward) || packet_size <= 1280,
        "relay-forward packet size exceeds negotiated maximum"
    );
    ensure!(duration >= Duration::from_millis(100) && duration <= Duration::from_secs(300));
    Ok(Options {
        mode: mode.context("--mode is required")?,
        flows,
        packet_size,
        duration,
    })
}

fn encode_packet(frame: &mut Frame, sequence: u64, mode: Mode) {
    let relay_mode = matches!(mode, Mode::Relay | Mode::RelayForward);
    let offset = usize::from(relay_mode) * 5;
    if relay_mode {
        frame.bytes[..5].copy_from_slice(
            &PacketHeader {
                version: 1,
                flags: 0,
                route_handle: (frame.flow + 1) as u32,
            }
            .encode()
            .expect("nonzero benchmark handle"),
        );
    }
    let packet = &mut frame.bytes[offset..frame.length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(frame.payload_length as u16).to_be_bytes());
    packet[12..16].copy_from_slice(&[100, 96, 0, (frame.flow % 250 + 1) as u8]);
    packet[16..20].copy_from_slice(&[100, 97, 0, (frame.flow % 250 + 1) as u8]);
    packet[20..28].copy_from_slice(&sequence.to_be_bytes());
}

fn node_dataplane(routes: &RoutingTable, frame: &Frame, output: &mut [u8; MAX_PACKET + 5]) -> bool {
    route_and_frame(routes, &frame.bytes[..frame.length], 1, output).is_some()
}

fn relay_dataplane(frame: &mut Frame) -> bool {
    let source = [100, 96, 0, (frame.flow % 250 + 1) as u8].into();
    let destination = [100, 97, 0, (frame.flow % 250 + 1) as u8].into();
    let return_handle = (frame.length % 65_534 + 1) as u32;
    validate_and_retag(
        &mut frame.bytes[..frame.length],
        source,
        destination,
        return_handle,
    )
}

fn node_routes(flows: usize) -> Result<RoutingTable> {
    let mut routes = Vec::with_capacity(flows);
    for flow in 0..flows {
        let mut id = [0_u8; 16];
        id[15] = (flow + 1) as u8;
        routes.push(RouteConfig {
            prefix: format!("100.97.0.{}/32", flow + 1).parse::<IpNet>()?,
            via_node: Id::new(id)?.to_string(),
            metric: 100,
            kind: RouteKind::Overlay,
        });
    }
    RoutingTable::compile(&routes)
}

fn process_ticks() -> Result<u64> {
    let text = fs::read_to_string("/proc/self/stat").context("read /proc/self/stat")?;
    let rest = text.rsplit_once(") ").context("parse /proc/self/stat")?.1;
    let fields: Vec<_> = rest.split_whitespace().collect();
    let user = fields.get(11).context("utime missing")?.parse::<u64>()?;
    let system = fields.get(12).context("stime missing")?.parse::<u64>()?;
    Ok(user + system)
}

fn rss_bytes() -> Result<u64> {
    let text = fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    let line = text
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .context("VmRSS missing")?;
    let kib = line
        .split_whitespace()
        .nth(1)
        .context("VmRSS value missing")?
        .parse::<u64>()?;
    Ok(kib * 1024)
}
