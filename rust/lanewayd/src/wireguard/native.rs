//! Native Linux ownership for the encrypted overlay profile.

use std::{
    collections::BTreeMap,
    fmt::Write,
    fs::OpenOptions,
    future::Future,
    io::{ErrorKind, Read},
    net::{Ipv4Addr, UdpSocket as StdUdpSocket},
    num::NonZeroU64,
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt},
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use laneway_protocol::Id;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use zeroize::Zeroizing;

use super::{MAX_WIREGUARD_DATAGRAM, WireGuardDatagram, WireGuardRelay, plan::DevicePlan};
use crate::{
    Config,
    controller::Snapshot,
    kernel::{CommandRunner, ExecRunner, KernelManager},
};

/// Native Linux WireGuard device with authenticated encrypted relay transport.
/// This profile does not install shared-host credentials or renew certificates.
pub struct WireGuardNode {
    relay: WireGuardRelay,
    private_key: Zeroizing<String>,
}

impl WireGuardNode {
    /// Validate the native profile and read the same raw 32-byte key format
    /// used by existing nodes. This does not create links or firewall state.
    pub fn new(config: Config, key_path: &Path, generation: Option<NonZeroU64>) -> Result<Self> {
        ensure!(
            config
                .controller
                .as_ref()
                .is_some_and(|c| !c.auto_renew_certificate)
                && !config.connector.userspace
                && !config.forwarding.subnet_router
                && !config.forwarding.exit_client.enabled
                && config.diagnostics.listen.is_none(),
            "native WireGuard requires controller authority without automatic certificate renewal, subnet forwarding, exit selection or diagnostics"
        );
        ensure!(
            config.tun.configure
                && config.tun.name != "lo"
                && config.tun.mtu == 1280
                && config
                    .tun
                    .name
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric),
            "native WireGuard requires a dedicated configured 1280-MTU device"
        );
        ensure!(
            !config.forwarding.exit_gateway || config.forwarding.exit_gateway_controller_sources,
            "native WireGuard NAT requires controller-approved source ownership"
        );
        ensure!(
            key_path.is_absolute(),
            "WireGuard private key path must be absolute"
        );
        config.validate()?;
        let private_key = read_private_key(key_path)?;
        let exec = ExecRunner::with_timeout(config.forwarding.shutdown_timeout);
        let public_key = exec.sensitive("wg", &["pubkey".to_owned()], private_key.as_bytes())?;
        let public_key = STANDARD
            .decode(std::str::from_utf8(&public_key)?.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid WireGuard public key"))?;
        let relay = WireGuardRelay::new(config, public_key, generation)?;
        Ok(Self { relay, private_key })
    }

    /// Join the controller, apply the live kernel snapshot, and remove the
    /// owned link and firewall when the session ends or the lease is revoked.
    pub async fn run_until(self, shutdown: impl Future<Output = ()>) -> Result<()> {
        let config = Arc::clone(&self.relay.config);
        let (outbound, relay_input) = mpsc::channel(config.relay.queue_depth);
        let (relay_output, mut inbound) = mpsc::channel(config.relay.queue_depth);
        let kernel = Arc::new(NativeKernel {
            node: config.ids()?.1,
            config,
            outbound,
            private_key: self.private_key,
            slot: Mutex::new(Slot::default()),
        });
        let adapter = async {
            while let Some(datagram) = inbound.recv().await {
                kernel.inject(datagram).await;
            }
            std::future::pending::<()>().await;
        };
        tokio::select! {
            result = self.relay.run(relay_input, relay_output, Some(Arc::clone(&kernel)), shutdown) => result,
            () = adapter => unreachable!("adapter runs until relay shutdown"),
        }
    }
}

pub(super) struct NativeKernel {
    node: Id,
    config: Arc<Config>,
    private_key: Zeroizing<String>,
    outbound: mpsc::Sender<WireGuardDatagram>,
    slot: Mutex<Slot>,
}

#[derive(Default)]
struct Slot {
    epoch: u64,
    active: Option<Device>,
}

impl NativeKernel {
    pub(super) async fn apply(&self, snapshot: Arc<Snapshot>, renewed: bool) -> Result<()> {
        let mut slot = self.slot.lock().await;
        ensure!(
            snapshot.epoch >= slot.epoch,
            "refuse an older native WireGuard configuration"
        );
        slot.epoch = snapshot.epoch;
        if renewed && let Some(device) = slot.active.as_mut() {
            device.snapshot = snapshot;
            return Ok(());
        }
        let plan = DevicePlan::compile(&self.config, &snapshot, self.node);
        if let Ok(plan) = &plan
            && let Some(device) = slot.active.as_mut()
            && device.plan.same_paths(plan)
        {
            if device.plan != *plan {
                if let Err(error) = device.replace_acl(plan) {
                    let mut device = slot.active.take().expect("active device checked above");
                    return Err(match device.close() {
                        Ok(()) => error,
                        Err(cleanup) => {
                            error.context(format!("WireGuard cleanup failed: {cleanup:#}"))
                        }
                    });
                }
                device.plan = plan.clone();
            }
            device.snapshot = snapshot;
            return Ok(());
        }
        // A changed security plan is never exposed on the old kernel link.
        // Any failure leaves the carrier detached until a later valid snapshot.
        if let Some(mut old) = slot.active.take() {
            old.close()?;
        }
        let next = Device::create(
            Arc::clone(&self.config),
            plan?,
            snapshot,
            &self.private_key,
            &self.outbound,
        );
        let device = next.context("apply native WireGuard configuration")?;
        tracing::info!(interface = %device.config.tun.name, "native Rust WireGuard device ready");
        slot.active = Some(device);
        Ok(())
    }

    pub(super) async fn fail_close(&self) -> Result<()> {
        if let Some(mut device) = self.slot.lock().await.active.take() {
            device.close()?;
        }
        Ok(())
    }

    async fn inject(&self, datagram: WireGuardDatagram) {
        let slot = self.slot.lock().await;
        if let Some(device) = slot
            .active
            .as_ref()
            .filter(|device| !device.snapshot.wireguard_authority_expired())
            && let Some(peer) = device
                .peers
                .get(&datagram.peer())
                .filter(|peer| peer.key == datagram.peer_key())
            && let Err(error) = peer.socket.try_send(datagram.payload())
        {
            tracing::trace!(%error, "drop WireGuard kernel datagram");
        }
    }
}

struct PeerSocket {
    socket: Arc<UdpSocket>,
    reader: JoinHandle<()>,
    key: [u8; 32],
}

impl Drop for PeerSocket {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

struct Device {
    config: Arc<Config>,
    exec: ExecRunner,
    ifindex: Option<u64>,
    table: String,
    listen_port: u16,
    owned_rules: Option<serde_json::Value>,
    forwarding: Option<KernelManager>,
    peers: BTreeMap<Id, PeerSocket>,
    plan: DevicePlan,
    snapshot: Arc<Snapshot>,
}

impl Device {
    fn create(
        config: Arc<Config>,
        plan: DevicePlan,
        snapshot: Arc<Snapshot>,
        private_key: &str,
        outbound: &mpsc::Sender<WireGuardDatagram>,
    ) -> Result<Self> {
        let exec = ExecRunner::with_timeout(config.forwarding.shutdown_timeout);
        // Hex encoding makes even a quoted/dashed interface safe as an nft name.
        let table = format!("lw_wg_{}", hex::encode(&config.tun.name));
        let mut device = Self {
            config,
            exec,
            ifindex: None,
            owned_rules: None,
            table,
            listen_port: 0,
            forwarding: None,
            peers: BTreeMap::new(),
            plan,
            snapshot,
        };
        if let Err(error) = device.activate(private_key, outbound) {
            return Err(match device.close() {
                Ok(()) => error,
                Err(cleanup) => error.context(format!("WireGuard rollback failed: {cleanup:#}")),
            });
        }
        Ok(device)
    }

    fn activate(
        &mut self,
        private_key: &str,
        outbound: &mpsc::Sender<WireGuardDatagram>,
    ) -> Result<()> {
        ensure!(
            !self.snapshot.wireguard_authority_expired(),
            "WireGuard authority expired before device activation"
        );
        let interface = &self.config.tun.name;
        self.ip(
            &["link", "add", "dev", interface, "type", "wireguard"],
            None,
        )
        .context("create dedicated WireGuard link (existing links are not adopted)")?;
        self.ifindex = Some(self.read_ifindex()?);
        self.ip(
            &[
                "link",
                "set",
                "dev",
                interface,
                "mtu",
                "1280",
                "addrgenmode",
                "none",
            ],
            None,
        )?;
        let port = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .context("reserve WireGuard loopback port")?;
        let listen_port = port.local_addr()?.port();
        self.listen_port = listen_port;
        // Compute a conservative bound up front so the buffer never grows
        // after it begins holding the base64 private key.
        let capacity = 96
            + self
                .plan
                .peers
                .values()
                .map(|peer| 144 + peer.prefixes.len() * 68)
                .sum::<usize>();
        let mut config = Zeroizing::new(String::with_capacity(capacity));
        writeln!(
            config,
            "[Interface]\nPrivateKey = {private_key}\nListenPort = {listen_port}"
        )?;
        let mut routes = String::new();
        for prefix in &self.plan.overlays {
            writeln!(
                routes,
                "address add {prefix} dev {interface}{}",
                if prefix.addr().is_ipv6() {
                    " nodad"
                } else {
                    ""
                }
            )?;
        }
        for (&id, peer) in &self.plan.peers {
            let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .context("bind WireGuard peer adapter")?;
            socket.set_nonblocking(true)?;
            socket.connect((Ipv4Addr::LOCALHOST, listen_port))?;
            let address = socket.local_addr()?;
            let socket = Arc::new(UdpSocket::from_std(socket)?);
            let mut allowed = Vec::with_capacity(peer.prefixes.len());
            for prefix in &peer.prefixes {
                writeln!(routes, "route add {prefix} dev {interface}")?;
                allowed.push(prefix.to_string());
            }
            write!(
                config,
                "\n[Peer]\nPublicKey = {}\nEndpoint = {address}\nAllowedIPs = {}\n",
                STANDARD.encode(peer.key),
                allowed.join(", ")
            )?;
            let key = peer.key;
            let reader_socket = Arc::clone(&socket);
            let outbound = outbound.clone();
            let reader = tokio::spawn(async move {
                let mut buffer = [0; MAX_WIREGUARD_DATAGRAM + 1];
                loop {
                    match reader_socket.recv(&mut buffer).await {
                        Ok(length) => {
                            if let Ok(packet) = WireGuardDatagram::new(
                                id,
                                key,
                                Bytes::copy_from_slice(&buffer[..length]),
                            ) {
                                let _ = outbound.try_send(packet);
                            }
                        }
                        Err(error) => {
                            tracing::trace!(%error, "WireGuard loopback receive failed");
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    }
                }
            });
            self.peers.insert(
                id,
                PeerSocket {
                    socket,
                    reader,
                    key,
                },
            );
        }
        self.exec.sensitive(
            "wg",
            &args(&["setconf", interface, "/dev/stdin"]),
            config.as_bytes(),
        )?;
        let rules = self.rules(&self.plan)?;
        self.nft(&["-f", "-"], Some(rules.as_bytes()))?;
        self.owned_rules = Some(self.read_table()?);
        if !self.plan.nat_sources.is_empty() {
            let mut config = (*self.config).clone();
            config
                .forwarding
                .exit_gateway_sources
                .clone_from(&self.plan.nat_sources);
            config.forwarding.exit_gateway_controller_sources = false;
            self.forwarding = Some(KernelManager::apply(Arc::new(config))?);
        }
        ensure!(
            !self.snapshot.wireguard_authority_expired(),
            "WireGuard authority expired while preparing device"
        );
        // Linux refuses nexthop routes until the device is up. The decrypted
        // firewall and peers are already in place; the relay remains suspended.
        drop(port);
        self.ip(&["link", "set", "dev", interface, "up"], None)?;
        self.ip(&["-batch", "-"], Some(routes.as_bytes()))?;
        ensure!(
            !self.snapshot.wireguard_authority_expired(),
            "WireGuard authority expired while applying routes"
        );
        Ok(())
    }

    fn rules(&self, plan: &DevicePlan) -> Result<String> {
        plan.firewall(
            &self.table,
            &self.config.tun.name,
            self.listen_port,
            self.config.forwarding.exit_output_interface.as_deref(),
        )
    }

    fn replace_acl(&mut self, plan: &DevicePlan) -> Result<()> {
        ensure!(
            self.owned_rules.as_ref() == Some(&self.read_table()?),
            "WireGuard nftables ownership changed"
        );
        let rules = format!("delete table inet {}\n{}", self.table, self.rules(plan)?);
        // No packet sees an unprotected interface between the old and new ACL.
        self.nft(&["-f", "-"], Some(rules.as_bytes()))?;
        self.owned_rules = Some(self.read_table()?);
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.peers.clear();
        // Never remove the guard or NAT state before disabling the device.
        if let Some(owned) = self.ifindex {
            ensure!(
                self.read_ifindex()? == owned,
                "WireGuard link ownership changed"
            );
            self.ip(&["link", "delete", "dev", &self.config.tun.name], None)?;
            self.ifindex = None;
        }
        if let Some(forwarding) = self.forwarding.as_mut() {
            forwarding.restore()?;
            self.forwarding = None;
        }
        if let Some(owned) = &self.owned_rules {
            ensure!(
                self.read_table()? == *owned,
                "WireGuard nftables ownership changed"
            );
            self.nft(&["delete", "table", "inet", &self.table], None)?;
            self.owned_rules = None;
        }
        Ok(())
    }

    fn read_ifindex(&self) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct Link {
            ifname: String,
            ifindex: u64,
            linkinfo: LinkInfo,
        }
        #[derive(serde::Deserialize)]
        struct LinkInfo {
            info_kind: String,
        }
        let name = &self.config.tun.name;
        let info = self.ip(&["-j", "-d", "link", "show", "dev", name], None)?;
        let links: Vec<Link> = serde_json::from_slice(&info)?;
        ensure!(
            links.len() == 1
                && links[0].ifname == *name
                && links[0].linkinfo.info_kind == "wireguard",
            "unexpected WireGuard link shape"
        );
        Ok(links[0].ifindex)
    }

    fn read_table(&self) -> Result<serde_json::Value> {
        let bytes = self.nft(&["-j", "list", "table", "inet", &self.table], None)?;
        let mut document: serde_json::Value = serde_json::from_slice(&bytes)?;
        // Packet counters can change during normal operation. Retain every
        // other field, including the presence and position of the counters.
        if let Some(entries) = document
            .get_mut("nftables")
            .and_then(serde_json::Value::as_array_mut)
        {
            for entry in entries {
                if let Some(expressions) = entry
                    .pointer_mut("/rule/expr")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for expression in expressions {
                        if let Some(counter) = expression
                            .get_mut("counter")
                            .and_then(serde_json::Value::as_object_mut)
                        {
                            for key in ["packets", "bytes"] {
                                if let Some(value) =
                                    counter.get_mut(key).filter(|value| value.is_u64())
                                {
                                    *value = 0.into();
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(document)
    }

    fn nft(&self, arguments: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
        self.exec
            .run(&self.config.forwarding.nft_command, &args(arguments), input)
    }

    fn ip(&self, arguments: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
        self.exec
            .run(&self.config.forwarding.ip_command, &args(arguments), input)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            tracing::error!(%error, "clean up native WireGuard device");
        }
    }
}

fn args(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|value| (*value).to_owned()).collect()
}

fn read_private_key(path: &Path) -> Result<Zeroizing<String>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open native WireGuard private key")?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid takes no pointers and reads only process identity.
    let owner = unsafe { libc::geteuid() };
    ensure!(
        metadata.is_file()
            && metadata.len() == 32
            && metadata.nlink() == 1
            && metadata.uid() == owner
            && matches!(metadata.mode() & 0o777, 0o600 | 0o640),
        "WireGuard key must be a single-linked owned raw 32-byte file with mode 0600 or 0640"
    );
    let mut raw = Zeroizing::new([0u8; 33]);
    file.read_exact(&mut raw[..32])?;
    match file.read_exact(&mut raw[32..]) {
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => (),
        Ok(()) => bail!("WireGuard key size changed while reading"),
        Err(error) => return Err(error).context("read native WireGuard key"),
    }
    ensure!(
        raw[..32].iter().any(|byte| *byte != 0),
        "WireGuard key must not be zero"
    );
    let mut encoded = Zeroizing::new(String::with_capacity(44));
    STANDARD.encode_string(&raw[..32], &mut encoded);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn only_an_owned_single_link_raw_private_key_is_read() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let path = fixture.path().join("wireguard.key");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&[42; 32])?;
        assert!(read_private_key(&path).is_ok());

        let other = fixture.path().join("link");
        symlink(&path, &other)?;
        assert!(read_private_key(&other).is_err());
        std::fs::remove_file(&other)?;
        std::fs::hard_link(&path, &other)?;
        assert!(read_private_key(&path).is_err());
        std::fs::remove_file(&other)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        assert!(read_private_key(&path).is_err());
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.set_len(33)?;
        assert!(read_private_key(&path).is_err());
        Ok(())
    }
}
