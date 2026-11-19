//! Trusted operator configuration for the shared controller and relay.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf};

/// A registry of explicitly provisioned hostnames. Unknown SNI never falls back.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// DNS name of the platform console and parent of the tenant hostnames.
    pub domain: String,
    /// Shared public HTTPS and authenticated fallback TCP listener.
    pub public_listen: SocketAddr,
    /// Optional existing control plane served at the base hostname.
    pub platform: Option<Deployment>,
    /// Tenant deployments with independent authority and state.
    pub tenants: Vec<Tenant>,
}

/// A tenant's DNS label and deployment inputs.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tenant {
    /// A single, canonical lowercase DNS label.
    pub slug: String,
    /// Paths and listeners allocated to this tenant.
    pub deployment: Deployment,
}

/// One independent controller identity, database, and relay configuration.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    /// Existing controller database.
    pub database: PathBuf,
    /// Workload and upstream HTTPS listener, unique in the process.
    pub controller_https: SocketAddr,
    /// Workload QUIC listener, unique in the process.
    pub controller_quic: SocketAddr,
    /// Controller workload certificate chain.
    pub controller_certificate: PathBuf,
    /// Private key for the controller workload certificate.
    pub controller_key: PathBuf,
    /// Protected root automation credential for this deployment only.
    pub root_token: PathBuf,
    /// Certificate chain of this deployment's node issuer.
    pub issuer_chain: PathBuf,
    /// Private key of this deployment's node issuer.
    pub issuer_key: PathBuf,
    /// Root trust anchor for this deployment's workloads.
    pub client_ca: PathBuf,
    /// Bootstrap discovery JSON, if public discovery is enabled.
    pub bootstrap_profile: Option<PathBuf>,
    /// Independent controller leaf renewal directory.
    pub controller_renewal_dir: Option<PathBuf>,
    /// TOML for this deployment's public HTTPS and data relay.
    pub relay_config: PathBuf,
}

impl Manifest {
    /// Returns exact hostname mappings after validating names, paths and listeners.
    pub fn entries(&self) -> Result<Vec<(String, &Deployment)>, &'static str> {
        if self.tenants.is_empty() {
            return Err("shared runtime requires at least one tenant");
        }
        self.directory_entries()
    }

    /// Validates a directory manifest, including an empty registry before its first tenant.
    pub fn directory_entries(&self) -> Result<Vec<(String, &Deployment)>, &'static str> {
        if self.domain.len() > 189
            || self.domain.split('.').count() < 2
            || !self.domain.split('.').all(label)
            || self.domain.parse::<std::net::IpAddr>().is_ok()
            || self.public_listen.port() == 0
            || self.tenants.len() > 64
        {
            return Err("invalid tenant registry domain, public listener, or tenant count");
        }
        let mut entries = Vec::new();
        if let Some(platform) = &self.platform {
            entries.push((self.domain.clone(), platform));
        }
        let mut names = BTreeSet::new();
        for tenant in &self.tenants {
            let slug = tenant.slug.as_str();
            if !valid_slug(slug) || !names.insert(slug) {
                return Err("duplicate, reserved, or invalid tenant slug");
            }
            entries.push((format!("{slug}.{}", self.domain), &tenant.deployment));
        }
        let mut https = BTreeSet::from([self.public_listen]);
        let mut quic = BTreeSet::new();
        for (_, item) in &entries {
            if item.controller_https.port() == 0
                || item.controller_quic.port() == 0
                || !https.insert(item.controller_https)
                || !quic.insert(item.controller_quic)
            {
                return Err("duplicate or ephemeral controller listener");
            }
            if ![
                &item.database,
                &item.controller_certificate,
                &item.controller_key,
                &item.root_token,
                &item.issuer_chain,
                &item.issuer_key,
                &item.client_ca,
                &item.relay_config,
            ]
            .into_iter()
            .chain(item.bootstrap_profile.iter())
            .chain(item.controller_renewal_dir.iter())
            .all(|path| {
                path.is_absolute()
                    && !path
                        .components()
                        .any(|part| part == std::path::Component::ParentDir)
            }) {
                return Err("tenant inputs must use absolute paths without parent traversal");
            }
        }
        Ok(entries)
    }
}

/// Returns whether the canonical label is available for tenant use.
pub fn valid_slug(s: &str) -> bool {
    label(s) && !matches!(s, "admin" | "api" | "www" | "platform")
}

fn label(s: &str) -> bool {
    let atom = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=63).contains(&s.len())
        && s.as_bytes().first().copied().is_some_and(atom)
        && s.as_bytes().last().copied().is_some_and(atom)
        && s.bytes().all(|c| atom(c) || c == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment(port: u16) -> Deployment {
        let path = |name| {
            std::env::temp_dir()
                .join(format!("laneway-{port}"))
                .join(name)
        };
        let listen = ([127, 0, 0, 1], port).into();
        Deployment {
            database: path("controller.db"),
            controller_https: listen,
            controller_quic: listen,
            controller_certificate: path("controller.crt"),
            controller_key: path("controller.key"),
            root_token: path("admin.token"),
            issuer_chain: path("issuer.crt"),
            issuer_key: path("issuer.key"),
            client_ca: path("ca.crt"),
            bootstrap_profile: None,
            controller_renewal_dir: None,
            relay_config: path("relay.toml"),
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            domain: "lane.test".into(),
            public_listen: ([127, 0, 0, 1], 443).into(),
            platform: Some(deployment(8443)),
            tenants: vec![
                Tenant {
                    slug: "alpha".into(),
                    deployment: deployment(8444),
                },
                Tenant {
                    slug: "beta-1".into(),
                    deployment: deployment(8445),
                },
            ],
        }
    }

    #[test]
    fn validates_an_empty_platform_without_starting_a_shared_runtime() {
        let mut config = manifest();
        config.tenants.clear();
        config.platform = None;
        assert!(config.directory_entries().unwrap().is_empty());
        assert!(config.entries().is_err());
        config.domain = "not/a-domain".into();
        assert!(config.directory_entries().is_err());
    }

    #[test]
    fn maps_the_base_and_exact_tenant_names() {
        let config = manifest();
        let names: Vec<_> = config
            .entries()
            .unwrap()
            .into_iter()
            .map(|(host, _)| host)
            .collect();
        assert_eq!(names, ["lane.test", "alpha.lane.test", "beta-1.lane.test"]);
    }

    #[test]
    fn rejects_ambiguous_names_and_listeners() {
        for slug in [
            "alpha",
            "platform",
            "ALPHA",
            "beta.lane.test",
            "-beta",
            "beta-",
        ] {
            let mut config = manifest();
            config.tenants[1].slug = slug.into();
            assert!(config.entries().is_err(), "{slug}");
        }
        let mut config = manifest();
        config.tenants[1].deployment.controller_https =
            config.tenants[0].deployment.controller_https;
        assert!(config.entries().is_err());
        let mut config = manifest();
        config.tenants[1].deployment.root_token = "relative.key".into();
        assert!(config.entries().is_err());
    }
}
