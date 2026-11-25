use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result, bail, ensure};
use reqwest::Method;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use super::{
    Operation,
    args::Flags,
    prefix::Prefix,
    transport::{Client, MAX_REQUEST, bounded},
};
use crate::utility::parse_duration;

const ADMIN: &str = "/v1/admin";
pub(super) const SUBNET_ROUTER: u32 = 1 << 3;
pub(super) const EXIT_NODE: u32 = 1 << 4;
const BUNDLE_PREFIX: &str = "/.well-known/laneway/bootstrap/";

pub(super) fn execute(operation: Operation, flags: &Flags<'_>) -> Result<Value> {
    use Operation::*;

    let client = || Client::new(flags, false);
    if let Some(collection) = operation.network_collection() {
        let path = format!(
            "{ADMIN}/networks/{}/{collection}?limit={}",
            flags.id("network-id")?,
            flags.limit()?
        );
        return client()?.get(&path);
    }
    let (method, path, body) = match operation {
        NetworkList => return client()?.get(&format!("{ADMIN}/networks?limit={}", flags.limit()?)),
        NetworkGet => {
            return client()?.get(&format!("{ADMIN}/networks/{}", flags.id("network-id")?));
        }
        NetworkCreate => {
            let pool: Prefix = flags.required("ipv4-pool")?.parse()?;
            ensure!(
                pool.addr.is_ipv4(),
                "network create requires a canonical IPv4 --ipv4-pool"
            );
            let mut request =
                json!({"name": flags.required("name")?, "ipv4_pool": pool.to_string()});
            if !flags.text("network-id")?.is_empty() {
                request["network_id"] = json!(flags.id("network-id")?.to_string());
            }
            if let Some(pool) = optional_prefix(flags.text("ipv6-pool")?)? {
                ensure!(
                    pool.addr.is_ipv6() && (64..=120).contains(&pool.bits),
                    "--ipv6-pool must be a canonical IPv6 /64 through /120"
                );
                request["ipv6_pool"] = json!(pool.to_string());
            }
            (Method::POST, format!("{ADMIN}/networks"), Some(request))
        }
        RelayRegister => {
            let network = flags.id("network-id")?;
            let mut request = json!({
                "service_id": flags.id("service-id")?.to_string(),
                "name": flags.required("name")?,
                "endpoint": flags.required("endpoint")?,
            });
            if !flags.text("node-id")?.is_empty() {
                request["node_id"] = json!(flags.id("node-id")?.to_string());
            }
            (
                Method::POST,
                format!("{ADMIN}/networks/{network}/relays"),
                Some(request),
            )
        }
        RelayUpdate => (
            Method::PUT,
            format!("{ADMIN}/relays/{}", flags.id("relay-id")?),
            Some(
                json!({"name": flags.required("name")?, "endpoint": flags.required("endpoint")?, "enabled": flags.boolean("enabled", true)?}),
            ),
        ),
        RelayDisable => (
            Method::POST,
            format!("{ADMIN}/relays/{}/disable", flags.id("relay-id")?),
            None,
        ),
        AclAdd => {
            let network = flags.id("network-id")?;
            let action = flags.enum_value("action", "", &["accept", "deny"])?;
            let priority = flags.number("priority", "0")?;
            let selector = flags.text("selector")?;
            let selector_file = flags.path("selector-file", "");
            ensure!(
                selector.is_empty() != selector_file.as_os_str().is_empty(),
                "acl add requires exactly one of --selector or --selector-file"
            );
            let selector: Value = if selector.is_empty() {
                serde_json::from_slice(&bounded(selector_file, MAX_REQUEST)?)
            } else {
                serde_json::from_str(selector)
            }
            .context("selector is not valid JSON")?;
            (
                Method::POST,
                format!("{ADMIN}/networks/{network}/acl-rules"),
                Some(
                    json!({"priority": priority, "action": action, "selector": selector, "description": flags.text("description")?}),
                ),
            )
        }
        AclDelete => (
            Method::DELETE,
            format!("{ADMIN}/acl-rules/{}", flags.id("rule-id")?),
            None,
        ),
        NodeRevoke => (
            Method::POST,
            format!("{ADMIN}/nodes/{}/revoke", flags.id("node-id")?),
            Some(json!({"reason": flags.required("reason")?})),
        ),
        NodeCapabilities => (
            Method::PUT,
            format!("{ADMIN}/nodes/{}/capabilities", flags.id("node-id")?),
            Some(json!({"enabled_capabilities": capabilities(flags, "subnet-router")?})),
        ),
        CertificateRevoke => {
            let serial = flags.required("serial")?;
            ensure!(
                serial.len() <= 64
                    && serial.len() % 2 == 0
                    && !serial.starts_with("00")
                    && serial
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "certificate revoke --serial must be canonical lowercase positive hexadecimal"
            );
            let reason = flags.required("reason")?;
            ensure!(
                reason == reason.trim(),
                "certificate revoke requires a canonical --reason"
            );
            (
                Method::POST,
                format!(
                    "{ADMIN}/networks/{}/certificates/{serial}/revoke",
                    flags.id("network-id")?
                ),
                Some(json!({"reason": reason})),
            )
        }
        EnrollmentIssue => return issue(flags),
        BootstrapCreate => return bootstrap(flags),
        _ => bail!("unsupported controller resource operation"),
    };
    client()?.request(method, &path, body)
}

fn optional_prefix(value: &str) -> Result<Option<Prefix>> {
    if value.is_empty() {
        Ok(None)
    } else {
        value.parse().map(Some)
    }
}

fn capabilities(flags: &Flags<'_>, subnet_flag: &str) -> Result<u32> {
    let subnet = flags.boolean(subnet_flag, false)?;
    let exit = flags.boolean("exit-node", false)?;
    if subnet_flag == "connector" {
        ensure!(
            !(subnet && exit),
            "choose either --connector or --exit-node"
        );
    }
    Ok((u32::from(subnet) * SUBNET_ROUTER) | (u32::from(exit) * EXIT_NODE))
}

fn issue(flags: &Flags<'_>) -> Result<Value> {
    let network = flags.id("network-id")?;
    let label = flags.required("label")?;
    let expires_in = parse_duration(flags.text_or("expires-in", "1h")?).context("--expires-in")?;
    ensure!(
        expires_in.is_positive(),
        "enrollment-token issue requires a positive --expires-in"
    );
    let class = flags.enum_value("class", "durable", &["durable", "ephemeral", "remembered"])?;
    let mut lifetime =
        parse_duration(flags.text_or("session-lifetime", "0")?).context("--session-lifetime")?;
    if class == "ephemeral" && lifetime.is_zero() {
        lifetime = Duration::hours(8);
    }
    ensure!(
        if class == "ephemeral" {
            lifetime.is_positive()
        } else {
            lifetime.is_zero()
        },
        "--session-lifetime is required only for ephemeral enrollment"
    );
    let mut body = json!({
        "network_id": network.to_string(), "label": label,
        "expires_at_unix_seconds": (OffsetDateTime::now_utc() + expires_in).unix_timestamp(),
        "enrollment_class": class,
    });
    if lifetime.whole_seconds() != 0 {
        body["session_lifetime_seconds"] = json!(lifetime.whole_seconds());
    }
    let name = flags.text("requested-name")?;
    if !name.is_empty() {
        body["requested_name"] = json!(name);
    }
    let capabilities = capabilities(flags, "connector")?;
    if capabilities != 0 {
        body["enabled_capabilities"] = json!(capabilities);
    }
    Client::new(flags, false)?.request(Method::POST, "/v1/admin/enrollment-tokens", Some(body))
}

fn bootstrap(flags: &Flags<'_>) -> Result<Value> {
    let path = flags.path("payload-file", "");
    let expiry = flags
        .required("expires-at")?
        .parse::<i64>()
        .context("--expires-at")?;
    ensure!(
        path.is_absolute() && expiry > 0,
        "bootstrap-bundle create requires an absolute --payload-file and --expires-at"
    );
    let info = std::fs::symlink_metadata(path).context("inspect bootstrap payload file")?;
    const MAX_BUNDLE: usize = 96 << 10;
    ensure!(
        info.is_file() && info.len() > 0 && info.len() <= MAX_BUNDLE as u64,
        "--payload-file must be a nonempty regular file within the bootstrap size limit"
    );
    ensure!(
        info.permissions().mode() & 0o077 == 0,
        "--payload-file must not be accessible by group or other users"
    );
    let payload = String::from_utf8(bounded(path, MAX_BUNDLE)?)
        .context("bootstrap payload must be valid UTF-8")?;
    let result = Client::new(flags, false)?.request(
        Method::POST,
        "/v1/admin/bootstrap-bundles",
        Some(json!({"payload":payload, "expires_at_unix_seconds":expiry})),
    )?;
    let id = result["bundle_id"]
        .as_str()
        .context("controller returned an invalid bootstrap bundle ID")?;
    ensure!(
        id.len() == 43
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            && result["public_path"] == format!("{BUNDLE_PREFIX}{id}")
            && result["expires_at_unix_seconds"] == expiry,
        "controller returned an invalid bootstrap bundle response"
    );
    Ok(result)
}
