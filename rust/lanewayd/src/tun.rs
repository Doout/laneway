use std::{collections::HashSet, process::Command, sync::Arc};

use anyhow::{Context, Result, bail, ensure};
use tokio_tun::Tun;

use crate::config::{RouteConfig, RouteKind, TunConfig};

/// Open native Linux TUN and the routes installed specifically for it.
pub struct TunDevice {
    device: Arc<Tun>,
    installed_routes: Vec<Vec<String>>,
    installed_addresses: Vec<String>,
    interface: String,
}

impl TunDevice {
    /// Creates the configured TUN and optionally installs addresses/routes.
    pub async fn open(config: &TunConfig, routes: &[RouteConfig]) -> Result<Self> {
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
        let device = Arc::new(devices.pop().expect("length checked"));
        let mut result = Self {
            device,
            installed_routes: Vec::new(),
            installed_addresses: Vec::new(),
            interface: config.name.clone(),
        };
        if config.configure
            && let Err(error) = result.configure(config, routes).await
        {
            let _ = result.restore().await;
            return Err(error);
        }
        Ok(result)
    }

    /// Returns the shareable asynchronous packet device.
    pub fn device(&self) -> Arc<Tun> {
        Arc::clone(&self.device)
    }

    async fn configure(&mut self, config: &TunConfig, routes: &[RouteConfig]) -> Result<()> {
        for address in &config.addresses {
            ip(&[
                "address",
                "add",
                &address.to_string(),
                "dev",
                &self.interface,
            ])
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
            ip(&["route", "add", &prefix, "dev", &self.interface]).await?;
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
    ) -> Result<()> {
        let desired_addresses: HashSet<String> =
            addresses.iter().map(ToString::to_string).collect();
        let current_addresses: HashSet<String> = self.installed_addresses.iter().cloned().collect();
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
                ip(&["address", "add", address, "dev", &self.interface]).await?;
                added_addresses.push(address.clone());
            }
            for route in desired_routes.difference(&current_routes) {
                ip(&["route", "add", route, "dev", &self.interface]).await?;
                added_routes.push(route.clone());
            }
            for route in current_routes.difference(&desired_routes) {
                ip(&["route", "delete", route, "dev", &self.interface]).await?;
                removed_routes.push(route.clone());
            }
            for address in current_addresses.difference(&desired_addresses) {
                ip(&["address", "delete", address, "dev", &self.interface]).await?;
                removed_addresses.push(address.clone());
            }
            Result::<()>::Ok(())
        }
        .await;
        if let Err(error) = result {
            let mut rollback_failures = Vec::new();
            for address in removed_addresses.iter().rev() {
                if let Err(rollback) =
                    ip(&["address", "add", address, "dev", &self.interface]).await
                {
                    rollback_failures.push(rollback);
                }
            }
            for route in removed_routes.iter().rev() {
                if let Err(rollback) = ip(&["route", "add", route, "dev", &self.interface]).await {
                    rollback_failures.push(rollback);
                }
            }
            for route in added_routes.iter().rev() {
                if let Err(rollback) = ip(&["route", "delete", route, "dev", &self.interface]).await
                {
                    rollback_failures.push(rollback);
                }
            }
            for address in added_addresses.iter().rev() {
                if let Err(rollback) =
                    ip(&["address", "delete", address, "dev", &self.interface]).await
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
        let mut failures = Vec::new();
        while let Some(route) = self.installed_routes.pop() {
            let mut arguments = vec!["route", "delete"];
            arguments.extend(route.iter().map(String::as_str));
            if let Err(error) = ip(&arguments).await {
                failures.push(error);
            }
        }
        while let Some(address) = self.installed_addresses.pop() {
            if let Err(error) = ip(&["address", "delete", &address, "dev", &self.interface]).await {
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

async fn ip(arguments: &[&str]) -> Result<()> {
    let output = Command::new("ip")
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
