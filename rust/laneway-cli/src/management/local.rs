use std::{
    ffi::OsString,
    io::{self, Write},
};

use anyhow::{Context, Result, ensure};
use laneway_config::Config;
use laneway_protocol::{Role, identity_from_certificate_der};
use reqwest::Method;
use serde_json::json;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    args::Flags,
    transport::{Client, bounded},
};
use crate::utility::parse_duration;

pub(super) fn invite(args: &[OsString]) -> Result<()> {
    let (mut flags, rest) = Flags::local(
        args,
        &["config", "name", "expires-in", "session-lifetime"],
        &["ephemeral", "remembered", "json"],
    )?;
    ensure!(rest.is_empty(), "invite: unexpected positional arguments");
    let name = flags.required("name")?;
    let ephemeral = flags.boolean("ephemeral", false)?;
    let remembered = flags.boolean("remembered", false)?;
    ensure!(
        !(ephemeral && remembered),
        "invite accepts either --ephemeral or --remembered"
    );
    let expiry = parse_duration(flags.text_or("expires-in", "10m")?)?;
    ensure!(
        expiry.is_positive() && expiry <= Duration::hours(1),
        "invalid --expires-in"
    );
    let class = if ephemeral {
        "ephemeral"
    } else if remembered {
        "remembered"
    } else {
        "durable"
    };
    let mut body = json!({
        "label": name, "requested_name": name, "enrollment_class": class,
        "expires_at_unix_seconds": (OffsetDateTime::now_utc() + expiry).unix_timestamp(),
    });
    if ephemeral {
        let lifetime = parse_duration(flags.text_or("session-lifetime", "8h")?)?;
        ensure!(lifetime.is_positive(), "invalid --session-lifetime");
        body["session_lifetime_seconds"] = json!(lifetime.whole_seconds());
    } else {
        ensure!(
            !flags.contains("session-lifetime"),
            "--session-lifetime is valid only with --ephemeral"
        );
    }

    let config = Config::load(flags.path("config", "/etc/laneway/controller.toml"))?;
    let bootstrap = &config.bootstrap;
    ensure!(
        config.mode == "controller" && !bootstrap.listen.is_empty(),
        "invite requires a controller configuration with public bootstrap enabled"
    );
    let pem = bounded(config.tls.certificate.as_ref(), 1 << 20)?;
    let der = rustls_pemfile::certs(&mut pem.as_slice())
        .next()
        .context("controller certificate is missing")??;
    let identity = identity_from_certificate_der(der.as_ref())?;
    ensure!(
        identity.role == Role::Controller
            && identity.network_id.to_string() == bootstrap.network_id,
        "bootstrap and controller certificate network identities do not match"
    );

    let service = identity.subject_id.to_string();
    flags.fallback("controller", &bootstrap.controller_endpoint);
    flags.fallback("ca", &config.tls.ca);
    flags.fallback("server-name", &bootstrap.controller_server_name);
    flags.fallback("controller-network-id", &bootstrap.network_id);
    flags.fallback("controller-service-id", &service);
    flags.fallback("admin-token-file", &config.controller.admin_token_file);
    body["network_id"] = json!(bootstrap.network_id);
    let listen = &config.controller.listen;
    let local_dial = ["0.0.0.0:", "[::]:", ":"]
        .iter()
        .find_map(|prefix| listen.strip_prefix(prefix))
        .map(|port| format!("127.0.0.1:{port}"));
    let client = Client::with_dial(&flags, false, Some(local_dial.as_deref().unwrap_or(listen)))?;
    let result = client.request(Method::POST, "/v1/admin/enrollment-tokens", Some(body))?;
    if flags.boolean("json", false)? {
        return super::print(&result);
    }
    let code = result["enrollment_token"]
        .as_str()
        .context("controller omitted enrollment token")?;
    ensure!(
        !code.is_empty()
            && code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "controller returned an invalid enrollment token"
    );
    let expiry = OffsetDateTime::from_unix_timestamp(
        result["expires_at_unix_seconds"]
            .as_i64()
            .context("controller omitted enrollment expiry")?,
    )?;
    writeln!(
        io::stderr().lock(),
        "Single-use {class} invite for {name} (expires {}):",
        expiry.format(&Rfc3339)?
    )?;
    writeln!(io::stdout().lock(), "{code}")?;
    Ok(())
}

pub(super) fn exit_enable(args: &[OsString]) -> Result<()> {
    let (mut flags, rest) = Flags::parse(
        args,
        &["config", "family", "mode", "metric", "valid-for"],
        &[],
        true,
    )?;
    ensure!(
        rest.is_empty(),
        "exit enable: unexpected positional arguments"
    );
    let family = flags.enum_value("family", "dual", &["dual", "ipv4", "ipv6"])?;
    let mode = flags.enum_value("mode", "nat", &["nat", "routed"])?;
    let metric = flags.number("metric", "0")?;
    let valid = parse_duration(flags.text_or("valid-for", "0")?)?;
    ensure!(!valid.is_negative(), "invalid --valid-for");
    let config = Config::load(flags.path("config", "/etc/laneway/laneway.toml"))?;
    ensure!(
        config.mode == "node" && config.exit.serve,
        "exit enable requires node mode with exit.serve=true"
    );
    flags.fallback("controller", &config.controller.endpoint);
    flags.fallback("ca", &config.tls.ca);
    flags.fallback("server-name", &config.controller.server_name);
    flags.fallback("controller-network-id", &config.controller.network_id);
    flags.fallback("controller-service-id", &config.controller.service_id);
    flags.fallback("cert", &config.tls.certificate);
    flags.fallback("key", &config.tls.private_key);
    let client = Client::new(&flags, true)?;
    let expires = (OffsetDateTime::now_utc() + valid).unix_timestamp();
    let mut advertisements = Vec::new();
    for (version, prefix) in [("ipv4", "0.0.0.0/0"), ("ipv6", "::/0")] {
        if family != "dual" && family != version {
            continue;
        }
        let mut body = json!({"prefix": prefix, "kind": "exit", "mode": mode, "metric": metric});
        if valid.is_positive() {
            body["valid_until_unix_seconds"] = json!(expires);
        }
        let route = client
            .request(Method::POST, "/v1/routes", Some(body))
            .with_context(|| {
                format!(
                    "advertise exit prefix {prefix} after {} successful request(s)",
                    advertisements.len()
                )
            })?;
        advertisements.push(route);
    }
    super::print(&json!({"advertisements": advertisements, "approval_needed": true}))
}
