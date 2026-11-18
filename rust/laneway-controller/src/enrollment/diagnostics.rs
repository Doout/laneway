//! Compare one flow with authoritative controller metadata without probing it.
use super::{
    configuration,
    policy_preview::{CheckedFlow, Evaluator, Flow, Unavailable, check_network},
    private_dns,
};
use crate::access_admin::AccessError;
use anyhow::{Context, Result, ensure};
use laneway_protocol::{Id, policy::prefix_from_wire};
use rusqlite::{OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostics {
    source_node_id: String,
    destination_node_id: Option<String>,
    destination_ip: Option<String>,
    protocol: String,
    #[serde(default)]
    destination_port: u16,
    #[serde(default)]
    dns_name: String,
}

#[derive(Serialize)]
struct Finding {
    category: &'static str,
    status: &'static str,
    code: String,
    summary: String,
    evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_step: Option<&'static str>,
}

impl Finding {
    fn new(
        category: &'static str,
        status: &'static str,
        code: impl Into<String>,
        summary: impl Into<String>,
        evidence: impl Into<String>,
        next_step: impl Into<Option<&'static str>>,
    ) -> Self {
        Self {
            category,
            status,
            code: code.into(),
            summary: summary.into(),
            evidence: evidence.into(),
            next_step: next_step.into(),
        }
    }
}

pub(crate) fn diagnose(
    tx: &Transaction<'_>,
    net: Id,
    now: i64,
    req: Result<Diagnostics>,
) -> Result<Value> {
    check_network(tx, net)?;
    let req = req?;
    let name = &req.dns_name;
    ensure!(
        name.len() <= 253 && !name.contains(['\0', '\r', '\n', ' ', '/', ':']),
        AccessError::Invalid("invalid dns_name")
    );
    let flow = Flow {
        source_node_id: req.source_node_id,
        destination_node_id: req.destination_node_id,
        destination_ip: req.destination_ip.clone(),
        protocol: req.protocol,
        destination_port: req.destination_port,
    }
    .check()?
    .bind_overlay(tx, net)?;

    let mut findings = Vec::new();
    endpoint(tx, net, now, flow.source, "source", &mut findings)?;
    route(tx, net, now, &flow, &mut findings)?;
    findings.extend([
        Finding::new("transport", "unknown", "path_not_probed",
            "The source-to-destination transport path has not been tested.",
            "No target-specific direct/relay handshake, packet delivery, or return-path observation is available.",
            "Test the path from the source and inspect endpoint transport status."),
        Finding::new("service", "unknown", "service_not_probed",
            "The destination service has not been contacted.",
            "Policy and route configuration cannot prove that an application is listening or that its host firewall permits traffic.",
            "Test the requested service from the source; check the destination listener and host firewall."),
    ]);

    let policy = match Evaluator::load(tx, net, now, &flow) {
        Ok(evaluator) => evaluator.current()?,
        Err(error) => {
            match error.downcast_ref::<Unavailable>() {
                Some(Unavailable::Inactive(_)) => findings.push(Finding::new(
                    "policy", "unknown", "policy_endpoint_inactive",
                    "Policy evaluation is unavailable for an inactive endpoint.",
                    "A source or destination enrollment is revoked or its lease has expired; no allow/deny result is asserted.",
                    "Resolve the credential or enrollment blocker before evaluating the flow.",
                )),
                Some(Unavailable::Unresolved) => {}
                None => return Err(error),
            }
            json!({
                "configuration_epoch": 0,
                "action": "unknown",
                "default_result": false,
                "destination_node_id": "",
                "destination_ip": req.destination_ip.unwrap_or_default(),
                "trace": [],
            })
        }
    };
    findings.push(dns(
        tx,
        net,
        now,
        flow.source,
        name,
        policy["destination_ip"]
            .as_str()
            .and_then(|s| s.parse().ok()),
    )?);
    Ok(json!({
        "checked_at_unix_seconds": now,
        "findings": findings,
        "policy": policy,
        "reachability": "unknown",
        "limitations": [
            "Read-only control-plane evidence, not an end-to-end connectivity test.",
            "No packets, handshakes, DNS requests, or application requests were sent.",
            "Configuration and endpoint status may change after this check.",
        ],
    }))
}

fn route(
    tx: &Transaction<'_>,
    net: Id,
    now: i64,
    flow: &CheckedFlow,
    out: &mut Vec<Finding>,
) -> Result<()> {
    if let Some(node) = flow.destination {
        endpoint(tx, net, now, node, "destination", out)?;
        out.push(Finding::new("route", "pass", "destination_node_known",
            "The destination node is registered in this network.",
            "Network-scoped node record exists; this does not establish that the target IP is on-link, route selection, or a direct or relayed path.",
            None));
        return Ok(());
    }
    let ip = flow.ip.context("validated flow without destination")?;
    let (mut matches, mut exits) = (0u32, 0u32);
    for route in configuration::advertised_routes(tx, net, now)? {
        let prefix = prefix_from_wire(route.destination.context("route missing prefix")?)?;
        if prefix.contains(&ip) {
            matches += 1;
            exits += u32::from(prefix.prefix_len() == 0);
        }
    }
    let (status, code, summary) = if matches > 0 {
        (
            "pass",
            "route_candidates",
            "Approved route configuration covers the destination.",
        )
    } else {
        (
            "unknown",
            "no_route_candidate",
            "No approved route candidate was found for this address.",
        )
    };
    out.push(Finding::new("route", status, code, summary,
        format!("{matches} approved, unexpired candidates; {exits} are default routes. This is configuration, not endpoint route selection or forwarding proof."),
        "Check the source's installed routes and selected exit, then test the destination service from that source."));
    Ok(())
}

struct Endpoint {
    revoked: bool,
    active: bool,
    valid_certificate: bool,
    observed: Option<i64>,
    expires: Option<i64>,
    configuration: Option<String>,
    routes: Option<String>,
    exit: Option<String>,
    epoch: Option<i64>,
    controller_epoch: i64,
}

fn endpoint(
    tx: &Transaction<'_>,
    net: Id,
    now: i64,
    node: Id,
    role: &'static str,
    out: &mut Vec<Finding>,
) -> Result<()> {
    let evidence = tx.query_row(
        "SELECT n.revoked_at IS NOT NULL, n.revoked_at IS NULL AND
                 (n.enrollment_class<>'ephemeral' OR coalesce(n.lease_expires_at>?1,0)),
                EXISTS(SELECT 1 FROM certificates c WHERE c.node_id=n.id AND c.network_id=n.network_id
                    AND c.revoked_at IS NULL AND c.not_before<=?1 AND c.not_after>?1),
                s.observed_at,s.expires_at,s.configuration_state,s.route_state,s.selected_exit_state,
                s.configuration_epoch,w.configuration_epoch
         FROM nodes n JOIN networks w ON w.id=n.network_id
         LEFT JOIN endpoint_status_latest s ON s.node_id=n.id AND s.network_id=n.network_id
         WHERE n.network_id=?2 AND n.id=?3",
        (now, net.as_bytes(), node.as_bytes()),
        |r| Ok(Endpoint {
            revoked: r.get(0)?, active: r.get(1)?, valid_certificate: r.get(2)?, observed: r.get(3)?,
            expires: r.get(4)?, configuration: r.get(5)?, routes: r.get(6)?, exit: r.get(7)?,
            epoch: r.get(8)?, controller_epoch: r.get(9)?,
        }),
    ).optional()?.ok_or(AccessError::Missing)?;
    let valid = evidence.active && evidence.valid_certificate;
    out.push(if valid {
        Finding::new("credentials", "pass", format!("{role}_credentials_valid"),
            format!("The {role} has a currently valid controller-issued credential."),
            "At least one unrevoked certificate is within its validity period. Possession and current use by the endpoint are not verified.", None)
    } else {
        Finding::new("credentials", "blocked", format!("{role}_credentials_inactive"),
            format!("The {role} has no active enrollment with a currently valid certificate."),
            format!("revoked={}; enrollment_active={}; valid_certificate={}", evidence.revoked, evidence.active, evidence.valid_certificate),
            "Review enrollment and certificate state; renew or re-enroll using the approved recovery workflow.")
    });

    let Some(observed) = evidence.observed else {
        out.push(Finding::new(
            "heartbeat",
            "unknown",
            format!("{role}_never_reported"),
            format!("No endpoint status report is available for the {role}."),
            "No controller-observed status timestamp is recorded.",
            "Check whether the endpoint is running and can reach its controller.",
        ));
        return Ok(());
    };
    let expires = evidence.expires.context("endpoint report has no expiry")?;
    let timestamps =
        format!("observed_at_unix_seconds={observed}; expires_at_unix_seconds={expires}");
    if !valid || observed > now || expires <= now {
        out.push(Finding::new(
            "heartbeat",
            "unknown",
            format!("{role}_status_stale"),
            format!("The {role} status report is stale or its enrollment is inactive."),
            timestamps,
            "Check whether the endpoint is running and can reach its controller.",
        ));
        return Ok(());
    }
    out.push(Finding::new(
        "heartbeat",
        "pass",
        format!("{role}_status_current"),
        format!("The controller recently received a status report from the {role}."),
        timestamps,
        "A current heartbeat does not prove reachability to the requested destination.",
    ));
    let reported = evidence.epoch.context("endpoint report has no epoch")?;
    let controller = evidence.controller_epoch;
    let configuration = if reported < controller {
        "stale"
    } else {
        evidence.configuration.as_deref().unwrap_or("")
    };
    let routes = evidence.routes.as_deref().unwrap_or("");
    let exit = evidence.exit.as_deref().unwrap_or("");
    let warning = matches!(configuration, "stale" | "expired")
        || matches!(routes, "degraded" | "unavailable")
        || matches!(exit, "degraded" | "unavailable");
    out.push(Finding::new("endpoint_configuration", if warning { "warning" } else { "unknown" },
        format!("{role}_runtime_report"), format!("The {role} reports its local configuration and route state."),
        format!("configuration={configuration}; routes={routes}; selected_exit={exit}; reported_epoch={reported}; controller_epoch={controller}. This is endpoint-reported aggregate state, not destination-specific proof."),
        "Compare the installed configuration and selected exit with the intended path."));
    Ok(())
}

fn dns(
    tx: &Transaction<'_>,
    net: Id,
    now: i64,
    node: Id,
    name: &str,
    destination: Option<IpAddr>,
) -> Result<Finding> {
    let mut finding = Finding::new(
        "dns",
        "unknown",
        "dns_not_checked",
        "DNS resolution has not been tested.",
        "No lookup was sent from the source endpoint. Controller configuration cannot establish source resolver behavior.",
        "Resolve the name on the source and compare its answer with the intended destination IP.",
    );
    if name.is_empty() {
        finding.code = "dns_not_requested".into();
        finding.summary = "The supplied destination uses a node or IP, not a DNS name.".into();
        finding.next_step = Some(
            "Supply dns_name to inspect configured private naming; source resolver reachability still requires an endpoint test.",
        );
    } else if let Some((addresses, expiry)) =
        private_dns::diagnostic_lookup(tx, net, node, now, name)?
    {
        if addresses.is_empty() {
            finding.code = "dns_name_not_in_catalog".into();
            finding.summary = "This name is absent from the source's private DNS catalog.".into();
            finding.evidence = "No source-visible configured record was found. Public DNS, other resolvers, resolver installation, and permission filtering are not tested by this check.".into();
        } else {
            if destination.is_some_and(|ip| addresses.contains(&ip)) {
                finding.status = "pass";
                finding.code = "dns_configured".into();
                finding.summary =
                    "A source-visible private DNS record is configured for this name.".into();
            } else {
                finding.status = "warning";
                finding.code = "dns_destination_mismatch".into();
                finding.summary =
                    "The configured private name does not include the tested destination IP."
                        .into();
            }
            let addresses = addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            finding.evidence = format!(
                "Configured addresses: {addresses}. Catalog valid until {expiry}. Source resolver behavior has not been tested."
            );
        }
    }
    Ok(finding)
}
