use std::net::IpAddr;

use anyhow::Result;
use clap::Args;
use ipnet::IpNet;
use lanewayd_rs::{ExitClientConfig, ExitFailureMode};
use lanewayd_rs::{ForwardingConfig, RouteConfig, RouteKind, run_exit_fixture};

#[derive(Args)]
pub(super) struct ExitClient {
    #[arg(long, default_value = "lane0")]
    interface: String,
    #[arg(long)]
    transport_bypass: IpAddr,
    #[arg(long)]
    ipv6: bool,
}

#[derive(Args)]
pub(super) struct ExitGateway {
    #[arg(long, default_value = "lane0")]
    input: String,
    #[arg(long, default_value = "wan0")]
    output: String,
    #[arg(long)]
    overlay_source: IpNet,
    #[arg(long)]
    overlay_source6: Option<IpNet>,
}

pub(super) async fn client(options: ExitClient) -> Result<()> {
    const GATEWAY: &str = "00000000000000000000000000000002";
    let mut prefixes = vec!["0.0.0.0/0"];
    if options.ipv6 {
        prefixes.push("::/0");
    }
    let routes = prefixes
        .into_iter()
        .map(|prefix| {
            Ok(RouteConfig {
                prefix: prefix.parse()?,
                via_node: GATEWAY.into(),
                metric: 0,
                kind: RouteKind::Exit,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let forwarding = ForwardingConfig {
        exit_client: ExitClientConfig {
            enabled: true,
            authorized: true,
            selected_node: Some(GATEWAY.into()),
            failure_mode: ExitFailureMode::Closed,
            transport_bypass: vec![options.transport_bypass],
            ..ExitClientConfig::default()
        },
        ..ForwardingConfig::default()
    };
    run_exit_fixture(&options.interface, forwarding, routes, "exit-client").await
}

pub(super) async fn gateway(options: ExitGateway) -> Result<()> {
    let forwarding = ForwardingConfig {
        exit_gateway: true,
        exit_gateway_sources: std::iter::once(options.overlay_source)
            .chain(options.overlay_source6)
            .collect(),
        exit_output_interface: Some(options.output),
        ..ForwardingConfig::default()
    };
    run_exit_fixture(&options.input, forwarding, Vec::new(), "exit-gateway").await
}
