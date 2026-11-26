//! Production Linux TUN and route reconciliation for the privileged helper.

mod exit_dns;
mod routes;
mod system;

use std::{
    fs::{self, File},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::Instant,
};

use anyhow::{Context, Result, ensure};

use super::{Backend, Change, Session, Setup, combine, serve_inherited};
use exit_dns::ExitDns;
use routes::Routes;
use system::Ip;

const STATE: &str = "/run/laneway-network-helper";

/// Starts the Linux helper using only its inherited endpoint and protected
/// namespace state.
pub fn serve(control: BorrowedFd<'_>) -> Result<()> {
    ensure!(
        laneway_private::is_root(),
        "Linux network helper must run as root"
    );
    serve_inherited(control, LinuxBackend)
}

struct LinuxBackend;

struct LinuxSession {
    packet: File,
    interface: String,
    ip: Ip,
    routes: Routes,
    exit_dns: ExitDns,
    _namespace_lock: File,
}

impl Backend for LinuxBackend {
    type Session = LinuxSession;

    fn setup(self, setup: Setup, deadline: Instant) -> Result<Self::Session> {
        ensure!(
            protected_path(Path::new("/run"), true)?,
            "unsafe Linux runtime directory"
        );
        let root = Path::new(STATE);
        laneway_private::ensure_directory(root).context("open protected helper state")?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .context("read Linux boot identity for helper recovery")?;
        let boot = boot.trim();
        ensure!(
            boot.len() == 36
                && boot.bytes().enumerate().all(|(index, byte)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit()
                    }
                }),
            "invalid Linux boot identity for helper recovery"
        );
        let namespace = root.join(format!("{boot}-{:016x}", system::namespace_cookie()?));
        laneway_private::ensure_directory(&namespace).context("open protected namespace state")?;
        let namespace_lock = laneway_private::try_lock(&namespace.join("split-routes.lock"))
            .context("another helper owns Linux split routes in this namespace")?;
        let ip = Ip::new(&namespace, &namespace_lock)?;
        Routes::recover(&ip, &namespace, deadline)
            .context("recover an interrupted split-route session")?;

        let interface_state = namespace.join(&setup.name);
        laneway_private::ensure_directory(&interface_state)
            .context("open protected interface state")?;
        let exit_dns = ExitDns::new(&setup.name, &interface_state, &namespace_lock, deadline)?;
        let (packet, index) = system::open_tun(&ip, &setup, deadline)?;
        let mut session = LinuxSession {
            _namespace_lock: namespace_lock,
            packet,
            interface: setup.name.clone(),
            routes: Routes::new(&namespace, setup.name, index),
            ip,
            exit_dns,
        };
        if let Err(error) = session.routes.apply(&session.ip, setup.routes, deadline) {
            let cleanup = session.restore(super::operation_deadline());
            return Err(combine(Err(error), cleanup).expect_err("setup failed"));
        }
        Ok(session)
    }
}

impl Session for LinuxSession {
    fn packet(&self) -> BorrowedFd<'_> {
        self.packet.as_fd()
    }

    fn interface(&self) -> &str {
        &self.interface
    }

    fn apply(&mut self, change: Change, deadline: Instant) -> Result<()> {
        match change {
            Change::Routes(routes) => self.routes.apply(&self.ip, routes, deadline),
            change => self.exit_dns.apply(change, deadline),
        }
    }

    fn restore(mut self, deadline: Instant) -> Result<()> {
        let exit = self.exit_dns.restore(deadline);
        let split = self.routes.restore(&self.ip, deadline);
        combine(exit, split)
    }
}

pub(super) fn protected_path(path: &Path, is_dir: bool) -> Result<bool> {
    ensure!(
        path.is_absolute(),
        "protected Linux helper path must be absolute"
    );
    for (index, component) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(component)?;
        let needs_directory = index != 0 || is_dir;
        let trusted = metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o022 == 0
            && if needs_directory {
                metadata.is_dir()
            } else {
                metadata.is_file() && metadata.mode() & 0o100 != 0
            };
        if !trusted {
            return Ok(false);
        }
    }
    Ok(true)
}
