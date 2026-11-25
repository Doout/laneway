#[cfg(not(target_os = "macos"))]
use std::{
    fs::File,
    io::{Read, Write},
};

use std::{collections::HashSet, io, net::IpAddr, process::Command, sync::Arc};

use anyhow::{Context, Result, bail, ensure};
#[cfg(not(target_os = "macos"))]
use tokio::io::unix::AsyncFd;
#[cfg(target_os = "linux")]
use tokio_tun::Tun;

use crate::{
    SessionNetwork, SessionRoutes,
    config::{RouteConfig, RouteKind, TunConfig},
};

pub(crate) enum PacketDevice {
    #[cfg(target_os = "linux")]
    Native(Tun),
    #[cfg(not(target_os = "macos"))]
    Adopted(AsyncFd<File>),
    #[cfg(target_os = "macos")]
    Utun(crate::UtunPackets),
}

impl PacketDevice {
    pub(crate) async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Native(device) => device.recv(packet).await,
            #[cfg(target_os = "macos")]
            Self::Utun(device) => device.recv(packet).await,
            #[cfg(not(target_os = "macos"))]
            Self::Adopted(device) => loop {
                let mut ready = device.readable().await?;
                if let Ok(result) = ready.try_io(|fd| fd.get_ref().read(packet)) {
                    return result;
                }
            },
        }
    }

    pub(crate) async fn send_all(&self, packet: &[u8]) -> io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Native(device) => device.send_all(packet).await,
            #[cfg(target_os = "macos")]
            Self::Utun(device) => device.send(packet).await,
            #[cfg(not(target_os = "macos"))]
            Self::Adopted(device) => loop {
                let mut ready = device.writable().await?;
                if let Ok(result) = ready.try_io(|fd| fd.get_ref().write(packet)) {
                    return result.and_then(|size| {
                        if size == packet.len() {
                            Ok(())
                        } else {
                            Err(io::ErrorKind::WriteZero.into())
                        }
                    });
                }
            },
        }
    }
}

/// A native Linux TUN or an adopted packet device with an external route owner.
pub struct TunDevice {
    device: Arc<PacketDevice>,
    helper: Option<Box<dyn SessionRoutes>>,
    installed_routes: Vec<Vec<String>>,
    installed_addresses: Vec<String>,
    interface: String,
    ip_command: String,
}

impl TunDevice {
    /// Creates the configured TUN and optionally installs addresses/routes.
    #[cfg(target_os = "linux")]
    pub async fn open(
        config: &TunConfig,
        routes: &[RouteConfig],
        ip_command: &str,
    ) -> Result<Self> {
        let mut devices = Tun::builder()
            .name(&config.name)
            .mtu(i32::from(config.mtu))
            .up()
            .close_on_exec()
            .build()
            .context("create Linux TUN (CAP_NET_ADMIN is required)")?;
        ensure!(
            devices.len() == 1,
            "TUN builder returned an unexpected queue count"
        );
        let device = Arc::new(PacketDevice::Native(devices.pop().expect("length checked")));
        let mut result = Self {
            device,
            helper: None,
            installed_routes: Vec::new(),
            installed_addresses: Vec::new(),
            interface: config.name.clone(),
            ip_command: ip_command.to_owned(),
        };
        if config.configure
            && let Err(error) = result.configure(config, routes).await
        {
            let _ = result.restore().await;
            return Err(error);
        }
        Ok(result)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn open(_: &TunConfig, _: &[RouteConfig], _: &str) -> Result<Self> {
        bail!("direct Linux TUN operations are unavailable on this platform")
    }

    /// Returns the shareable asynchronous packet device.
    pub fn device(&self) -> Arc<PacketDevice> {
        Arc::clone(&self.device)
    }

    pub(crate) async fn adopt(config: &TunConfig, mut network: SessionNetwork) -> Result<Self> {
        #[cfg(not(target_os = "macos"))]
        let device = AsyncFd::new(network.packet).map(PacketDevice::Adopted);
        #[cfg(target_os = "macos")]
        let device = crate::UtunPackets::adopt(network.packet.into()).map(PacketDevice::Utun);
        let device = match device {
            Ok(device) => device,
            Err(error) => {
                let _ = network.routes.close().await;
                return Err(error).context("register inherited TUN descriptor");
            }
        };
        Ok(Self {
            device: Arc::new(device),
            helper: Some(network.routes),
            installed_routes: Vec::new(),
            installed_addresses: config.addresses.iter().map(ToString::to_string).collect(),
            #[cfg(not(target_os = "macos"))]
            interface: config.name.clone(),
            #[cfg(target_os = "macos")]
            interface: network.interface_name,
            ip_command: String::new(),
        })
    }

    pub(crate) fn helper(&self) -> Option<&dyn SessionRoutes> {
        self.helper.as_deref()
    }

    #[cfg(target_os = "linux")]
    async fn configure(&mut self, config: &TunConfig, routes: &[RouteConfig]) -> Result<()> {
        for address in &config.addresses {
            ip(
                &self.ip_command,
                &[
                    "address",
                    "add",
                    &address.to_string(),
                    "dev",
                    &self.interface,
                ],
            )
            .await?;
            self.installed_addresses.push(address.to_string());
        }

        for route in routes {
            // Exit defaults live only in the dedicated policy table owned by
            // KernelManager; they must never contaminate the main table.
            if route.kind == RouteKind::Exit {
                continue;
            }
            let prefix = route.prefix.to_string();
            ip(
                &self.ip_command,
                &["route", "add", &prefix, "dev", &self.interface],
            )
            .await?;
            self.installed_routes
                .push(vec![prefix, "dev".into(), self.interface.clone()]);
        }
        Ok(())
    }

    /// Atomically reconciles controller-owned interface addresses and main
    /// table TUN routes. Any failed command restores the prior owned set.
    pub(crate) async fn apply_controller(
        &mut self,
        addresses: &[ipnet::IpNet],
        routes: &[RouteConfig],
        bypasses: &[IpAddr],
    ) -> Result<()> {
        let desired_addresses: HashSet<String> =
            addresses.iter().map(ToString::to_string).collect();
        let current_addresses: HashSet<String> = self.installed_addresses.iter().cloned().collect();
        if let Some(helper) = &mut self.helper {
            ensure!(
                desired_addresses.is_empty() || desired_addresses == current_addresses,
                "controller attempted to change the active TUN overlay assignment"
            );
            return helper.apply(routes, bypasses).await;
        }
        let desired_routes: HashSet<String> = routes
            .iter()
            .filter(|route| route.kind != RouteKind::Exit)
            .map(|route| route.prefix.to_string())
            .collect();
        let current_routes: HashSet<String> = self
            .installed_routes
            .iter()
            .filter_map(|route| route.first().cloned())
            .collect();

        let mut added_addresses = Vec::new();
        let mut added_routes = Vec::new();
        let mut removed_routes = Vec::new();
        let mut removed_addresses = Vec::new();
        let result = async {
            for address in desired_addresses.difference(&current_addresses) {
                ip(
                    &self.ip_command,
                    &["address", "add", address, "dev", &self.interface],
                )
                .await?;
                added_addresses.push(address.clone());
            }
            for route in desired_routes.difference(&current_routes) {
                ip(
                    &self.ip_command,
                    &["route", "add", route, "dev", &self.interface],
                )
                .await?;
                added_routes.push(route.clone());
            }
            for route in current_routes.difference(&desired_routes) {
                ip(
                    &self.ip_command,
                    &["route", "delete", route, "dev", &self.interface],
                )
                .await?;
                removed_routes.push(route.clone());
            }
            for address in current_addresses.difference(&desired_addresses) {
                ip(
                    &self.ip_command,
                    &["address", "delete", address, "dev", &self.interface],
                )
                .await?;
                removed_addresses.push(address.clone());
            }
            Result::<()>::Ok(())
        }
        .await;
        if let Err(error) = result {
            let mut rollback_failures = Vec::new();
            for address in removed_addresses.iter().rev() {
                if let Err(rollback) = ip(
                    &self.ip_command,
                    &["address", "add", address, "dev", &self.interface],
                )
                .await
                {
                    rollback_failures.push(rollback);
                }
            }
            for route in removed_routes.iter().rev() {
                if let Err(rollback) = ip(
                    &self.ip_command,
                    &["route", "add", route, "dev", &self.interface],
                )
                .await
                {
                    rollback_failures.push(rollback);
                }
            }
            for route in added_routes.iter().rev() {
                if let Err(rollback) = ip(
                    &self.ip_command,
                    &["route", "delete", route, "dev", &self.interface],
                )
                .await
                {
                    rollback_failures.push(rollback);
                }
            }
            for address in added_addresses.iter().rev() {
                if let Err(rollback) = ip(
                    &self.ip_command,
                    &["address", "delete", address, "dev", &self.interface],
                )
                .await
                {
                    rollback_failures.push(rollback);
                }
            }
            ensure!(
                rollback_failures.is_empty(),
                "controller network reconciliation failed: {error:#}; rollback failed: {rollback_failures:?}"
            );
            return Err(error.context("controller network reconciliation rolled back"));
        }
        self.installed_addresses = desired_addresses.into_iter().collect();
        self.installed_routes = desired_routes
            .into_iter()
            .map(|prefix| vec![prefix, "dev".into(), self.interface.clone()])
            .collect();
        Ok(())
    }

    /// Removes only routes and addresses successfully installed by this process.
    pub async fn restore(&mut self) -> Result<()> {
        if let Some(mut helper) = self.helper.take() {
            return helper.close().await;
        }
        let mut failures = Vec::new();
        while let Some(route) = self.installed_routes.pop() {
            let mut arguments = vec!["route", "delete"];
            arguments.extend(route.iter().map(String::as_str));
            if let Err(error) = ip(&self.ip_command, &arguments).await {
                failures.push(error);
            }
        }
        while let Some(address) = self.installed_addresses.pop() {
            if let Err(error) = ip(
                &self.ip_command,
                &["address", "delete", &address, "dev", &self.interface],
            )
            .await
            {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("restore Linux network state: {failures:?}")
        }
    }
}

async fn ip(command: &str, arguments: &[&str]) -> Result<()> {
    let output = Command::new(command)
        .args(arguments)
        .output()
        .with_context(|| format!("run ip {}", arguments.join(" ")))?;
    ensure!(
        output.status.success(),
        "ip {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;

    #[test]
    fn default_split_is_family_specific() {
        let v4: IpNet = "0.0.0.0/0".parse().unwrap();
        let v6: IpNet = "::/0".parse().unwrap();
        assert!(matches!(v4, IpNet::V4(_)));
        assert!(matches!(v6, IpNet::V6(_)));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod darwin_tests {
    use std::{
        fs::File,
        future::Future,
        os::{fd::OwnedFd, unix::net::UnixDatagram},
        pin::Pin,
        sync::Mutex,
    };

    use super::*;

    struct Owner(Arc<Mutex<Vec<String>>>);

    impl SessionRoutes for Owner {
        fn apply<'a>(
            &'a mut self,
            routes: &'a [RouteConfig],
            bypasses: &'a [IpAddr],
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.0
                    .lock()
                    .unwrap()
                    .push(format!("{} through {}", routes[0].prefix, bypasses[0]));
                Ok(())
            })
        }

        fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                self.0.lock().unwrap().push("closed".into());
                Ok(())
            })
        }

        fn stopped(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn adopted_darwin_device_pumps_ip_and_uses_external_route_owner() {
        let (device, synthetic_kernel) = UnixDatagram::pair().unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let config = TunConfig {
            name: "utun".into(),
            mtu: 1280,
            addresses: vec!["100.64.0.2/32".parse().unwrap()],
            configure: true,
        };
        let mut tun = TunDevice::adopt(
            &config,
            SessionNetwork {
                packet: File::from(OwnedFd::from(device)),
                interface_name: "utun5".into(),
                routes: Box::new(Owner(Arc::clone(&trace))),
            },
        )
        .await
        .unwrap();
        assert_eq!(tun.interface, "utun5");
        let packet_device = tun.device();
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[9] = 1;
        let mut frame = 2_u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&packet);
        synthetic_kernel.send(&frame).unwrap();
        let mut actual = [0; 1280];
        let count = packet_device.recv(&mut actual).await.unwrap();
        assert_eq!(&actual[..count], &packet);
        packet_device.send_all(&packet).await.unwrap();
        let count = synthetic_kernel.recv(&mut actual).unwrap();
        assert_eq!(&actual[..count], &frame);

        tun.apply_controller(
            &config.addresses,
            &[RouteConfig {
                prefix: "192.0.2.0/24".parse().unwrap(),
                via_node: "000102030405060708090a0b0c0d0e0f".into(),
                metric: 4,
                kind: RouteKind::Subnet,
            }],
            &["198.51.100.1".parse().unwrap()],
        )
        .await
        .unwrap();
        tun.restore().await.unwrap();
        assert_eq!(
            *trace.lock().unwrap(),
            ["192.0.2.0/24 through 198.51.100.1", "closed"]
        );
    }
}
