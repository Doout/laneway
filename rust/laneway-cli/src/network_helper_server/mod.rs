//! Inherited privileged network-helper protocol.
//!
//! Platform backends own interface setup, scoped routing, and cleanup.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
mod platform_darwin;
#[cfg_attr(target_os = "macos", path = "security_darwin.rs")]
mod security;
#[cfg_attr(target_os = "macos", path = "socket_darwin.rs")]
mod socket;
mod wire;

use std::{
    os::fd::BorrowedFd,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};

#[cfg(target_os = "macos")]
pub use platform_darwin::serve_darwin;
pub use wire::{ExitPlan, Route, RoutePlan, Setup};
use wire::{MAX_MESSAGE, Operation, Reply, Request, VERSION};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Mutations allowed after setup. The backend applies each snapshot atomically
/// or reports failure with its previous state restored.
pub enum Change {
    Routes(RoutePlan),
    Exit(ExitPlan),
    RestoreExit,
    Dns(Vec<std::net::IpAddr>),
    RestoreDns,
}

/// Backend responsible for protecting host state before opening the TUN.
pub trait Backend {
    type Session: Session;

    /// On failure, clean up any partially installed state. Persist sufficient
    /// ownership information to recover from process death during setup.
    fn setup(self, request: Setup, deadline: Instant) -> Result<Self::Session>;
}

/// An active, journaled OS session. Only the packet descriptor is transferred.
pub trait Session {
    fn packet(&self) -> BorrowedFd<'_>;
    fn interface(&self) -> &str;
    fn apply(&mut self, change: Change, deadline: Instant) -> Result<()>;

    /// Restore DNS and policy routes, then close the interface. Must leave
    /// recoverable journal state if restoration fails.
    fn restore(self, deadline: Instant) -> Result<()>;
}

/// Serves a connected, unnamed Unix socket in a dedicated helper process.
/// Linux uses seqpacket and macOS uses a length-framed stream. The caller must
/// keep the socket out of child command stdio and provide a backend that
/// enforces its operation deadlines.
pub fn serve_inherited(control: BorrowedFd<'_>, backend: impl Backend) -> Result<()> {
    let channel = socket::Channel::open(control)?;
    security::require_single_thread()?;
    #[cfg(target_os = "linux")]
    let channel = {
        let mut channel = channel;
        channel.watch_shutdown().context("watch helper SIGTERM")?;
        channel
    };
    security::isolate_process_group()?;
    serve(channel, backend, security::harden_process)
}

fn serve(
    channel: socket::Channel,
    backend: impl Backend,
    harden: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut buffer = Box::new([0u8; MAX_MESSAGE]);
    let first = read(&channel, &mut buffer)?.context("helper peer closed before setup")?;
    let id = first.id;
    let setup = match first.operation() {
        Ok(Operation::Setup(setup)) => setup,
        Ok(_) => {
            return reject(
                &channel,
                id,
                anyhow!("first helper operation must be setup"),
            );
        }
        Err(error) => return reject(&channel, id, error),
    };
    let session = match backend.setup(setup, operation_deadline()) {
        Ok(session) => session,
        Err(error) => return reject(&channel, id, error),
    };
    let result = (|| {
        if let Err(error) = harden().context("reduce helper privileges") {
            return reject(&channel, id, error);
        }
        ensure!(
            wire::valid_interface(session.interface()),
            "invalid backend interface name"
        );
        respond(
            &channel,
            id,
            &Ok(()),
            Some((session.interface(), session.packet())),
        )
    })();
    let mut session = session;
    let outcome = result.and_then(|()| serve_active(&channel, &mut buffer, &mut session, id));
    let restore = session
        .restore(operation_deadline())
        .context("restore helper session");
    match outcome {
        Ok(Some((close_id, result))) => {
            let result = combine(result, restore);
            respond(&channel, close_id, &result, None)?;
            result
        }
        Ok(None) => restore,
        Err(error) => combine(Err(error), restore),
    }
}

fn combine(result: Result<()>, restore: Result<()>) -> Result<()> {
    match (result, restore) {
        (Ok(()), restore) => restore,
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(restore)) => Err(error.context(format!("{restore:#}"))),
    }
}

fn serve_active(
    channel: &socket::Channel,
    buffer: &mut [u8; MAX_MESSAGE],
    session: &mut impl Session,
    mut last_id: u64,
) -> Result<Option<(u64, Result<()>)>> {
    while let Some(request) = read(channel, buffer)? {
        let id = request.id;
        if id <= last_id {
            let error = Err(anyhow!("request IDs must increase monotonically"));
            respond(channel, id, &error, None)?;
            continue;
        }
        last_id = id;
        let closing = request.is_close();
        let change = match request.operation() {
            Ok(Operation::Setup(_)) => Err(anyhow!("helper setup already completed")),
            Ok(Operation::ApplyRoutes(plan)) => Ok(Change::Routes(plan)),
            Ok(Operation::ApplyExit(plan)) => Ok(Change::Exit(plan)),
            Ok(Operation::RestoreExit) => Ok(Change::RestoreExit),
            Ok(Operation::ApplyDns(servers)) => Ok(Change::Dns(servers)),
            Ok(Operation::RestoreDns) => Ok(Change::RestoreDns),
            Ok(Operation::Close) => return Ok(Some((id, Ok(())))),
            Err(error) if closing => return Ok(Some((id, Err(error)))),
            Err(error) => Err(error),
        };
        let result = change.and_then(|change| session.apply(change, operation_deadline()));
        respond(channel, id, &result, None)?;
    }
    Ok(None)
}

fn read(channel: &socket::Channel, buffer: &mut [u8; MAX_MESSAGE]) -> Result<Option<Request>> {
    channel
        .read(buffer)?
        .map(|length| Request::decode(&buffer[..length]))
        .transpose()
}

fn operation_deadline() -> Instant {
    Instant::now() + OPERATION_TIMEOUT
}

fn reject(channel: &socket::Channel, id: u64, error: anyhow::Error) -> Result<()> {
    let result = Err(error);
    respond(channel, id, &result, None)?;
    result
}

// Use only the packet descriptor and interface name in a successful setup
// reply. Other replies do not carry descriptive metadata or SCM_RIGHTS.
fn respond(
    channel: &socket::Channel,
    id: u64,
    result: &Result<()>,
    session: Option<(&str, BorrowedFd<'_>)>,
) -> Result<()> {
    let error = result
        .as_ref()
        .err()
        .map(|error| format!("{error:#}").chars().take(1024).collect::<String>());
    let bytes = serde_json::to_vec(&Reply {
        version: VERSION,
        id,
        ok: result.is_ok(),
        error: error.as_deref(),
        helper_pid: session.map(|_| std::process::id()),
        interface_name: session.map(|(interface, _)| interface),
    })?;
    channel.write(&bytes, session.map(|(_, packet)| packet))
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
