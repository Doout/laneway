#![forbid(unsafe_code)]

mod model;
mod validate;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub use model::*;

const MAX_FILE_SIZE: u64 = 1 << 20;

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("open configuration {}", path.display()))?;
        let mut contents = Vec::new();
        file.take(MAX_FILE_SIZE + 1)
            .read_to_end(&mut contents)
            .context("read configuration")?;
        ensure!(
            contents.len() as u64 <= MAX_FILE_SIZE,
            "configuration exceeds {MAX_FILE_SIZE} bytes"
        );
        Self::parse(std::str::from_utf8(&contents).context("configuration is not UTF-8")?)
    }

    pub fn parse(contents: &str) -> Result<Self> {
        ensure!(
            contents.len() as u64 <= MAX_FILE_SIZE,
            "configuration exceeds {MAX_FILE_SIZE} bytes"
        );
        let mut config: Config = toml::from_str(contents).context("decode configuration")?;
        // The Go schema enables direct connections only when the node omits
        // the setting. An explicit false survives decoding.
        if config.mode == "node" && config.direct.enabled.is_none() {
            config.direct.enabled = Some(true);
        }
        config.validate()?;
        Ok(config)
    }

    pub fn local_socket(&self) -> &Path {
        Path::new(&self.socket_path)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GoDuration(i64);

impl GoDuration {
    pub fn nanos(self) -> i64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for GoDuration {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        parse_duration(&text)
            .map(Self)
            .context("invalid Go duration")
            .map_err(serde::de::Error::custom)
    }
}

fn parse_duration(value: &str) -> Result<i64> {
    let (negative, mut text) = if let Some(text) = value.strip_prefix('-') {
        (true, text)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    if text == "0" {
        return Ok(0);
    }
    ensure!(!text.is_empty(), "empty duration");
    let mut total = 0_i128;
    while !text.is_empty() {
        let whole_end = text.bytes().take_while(u8::is_ascii_digit).count();
        let (whole, rest) = text.split_at(whole_end);
        let (fraction, rest) = if let Some(rest) = rest.strip_prefix('.') {
            let fraction_end = rest.bytes().take_while(u8::is_ascii_digit).count();
            rest.split_at(fraction_end)
        } else {
            ("", rest)
        };
        ensure!(
            !whole.is_empty() || !fraction.is_empty(),
            "duration number is missing"
        );
        let units = [
            ("ns", 1_i128),
            ("us", 1_000),
            ("µs", 1_000),
            ("μs", 1_000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ];
        let (suffix, multiplier) = units
            .into_iter()
            .find(|(suffix, _)| rest.starts_with(suffix))
            .context("duration unit is missing or unsupported")?;
        text = &rest[suffix.len()..];
        let integer = if whole.is_empty() {
            0
        } else {
            whole.parse::<i128>()?
        };
        let mut part = integer
            .checked_mul(multiplier)
            .context("duration overflow")?;
        if !fraction.is_empty() {
            // Each supported unit is at most 13 significant nanosecond digits.
            let fraction = &fraction[..fraction.len().min(18)];
            part = part
                .checked_add(
                    fraction.parse::<i128>()? * multiplier / 10_i128.pow(fraction.len() as u32),
                )
                .context("duration overflow")?;
        }
        total = total.checked_add(part).context("duration overflow")?;
        ensure!(
            total <= i128::from(i64::MAX) + i128::from(negative),
            "duration overflow"
        );
    }
    Ok(i64::try_from(if negative { -total } else { total })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    const CONTROLLER: &str = r#"
mode = "controller"
state_dir = "/var/lib/controller"
socket_path = "/run/controller.sock"
[tls]
certificate = "controller.crt"
private_key = "controller.key"
ca = "ca.crt"
[controller]
quic_listen = "127.0.0.1:8443"
database = "/var/lib/controller/controller.db"
ca_private_key = "issuer.key"
admin_token_file = "admin-token"
"#;

    const INITIAL: &str = r#"
[controller.initial_network]
network_id = "11111111111111111111111111111111"
name = "production"
ipv4_pool = "100.96.0.0/16"
ipv6_pool = "fd00:96::/64"
"#;

    #[test]
    fn parses_go_deployment_examples() {
        for contents in [
            include_str!("../../../deploy/examples/controller.toml"),
            include_str!("../../../deploy/examples/node-controller.toml"),
            include_str!("../../../deploy/examples/node.toml"),
            include_str!("../../../deploy/examples/relay-controller.toml"),
            include_str!("../../../deploy/examples/relay.toml"),
        ] {
            Config::parse(contents).unwrap();
        }
    }

    #[test]
    fn controller_network_schema_is_strict_and_preserves_socket_and_pools() {
        let config = Config::parse(&format!("{CONTROLLER}{INITIAL}")).unwrap();
        assert_eq!(config.local_socket(), Path::new("/run/controller.sock"));
        assert_eq!(config.controller.initial_network.ipv6_pool, "fd00:96::/64");
        let default =
            Config::parse(&CONTROLLER.replace("socket_path = \"/run/controller.sock\"", ""))
                .unwrap();
        assert_eq!(
            default.local_socket(),
            Path::new("/run/laneway/lanewayd.sock")
        );
        for invalid in [
            format!("{CONTROLLER}{INITIAL}future_feature = true"),
            format!("{CONTROLLER}{INITIAL}name = \"duplicate\""),
            format!("{CONTROLLER}{INITIAL}").replace("100.96.0.0/16", "100.96.0.2/16"),
            format!("{CONTROLLER}{INITIAL}").replace("fd00:96::/64", "fe80::/64"),
        ] {
            assert!(Config::parse(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn reads_go_duration_syntax_and_rejects_unsupported_units_or_overflow() {
        assert_eq!(parse_duration("+2h3.25m").unwrap(), 7_395_000_000_000);
        assert_eq!(parse_duration("-.1µs").unwrap(), -100);
        assert_eq!(parse_duration("0").unwrap(), 0);
        assert_eq!(parse_duration("-9223372036854775808ns").unwrap(), i64::MIN);
        for invalid in ["", "1", "1d", "1 2s", "++1s", "9223372036854775808ns"] {
            assert!(parse_duration(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn compares_malformed_cases_to_go_cli_when_enabled() {
        let Some(go) = std::env::var_os("LANEWAY_GO_CONFIG_BIN") else {
            return;
        };
        assert!(Path::new(&go).is_absolute());
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        let full = format!("{CONTROLLER}{INITIAL}");
        let cases = [
            CONTROLLER.to_owned(),
            full.clone(),
            full.replace("ipv6_pool", "unexpected_key"),
            full.replace("100.96.0.0/16", "100.96.1.0/16"),
            full.replace("fd00:96::/64", "::ffff:192.0.2.0/120"),
            full.clone() + "\n[direct]\nenabled = true",
            format!("{full}\n[tcp_fallback]\nkeepalive_period = \"3h\""),
            format!("{full}\n[bootstrap]\nnetwork_id = \"11111111111111111111111111111111\""),
            format!(
                "{full}\n[bootstrap]\nnetwork_id = \"22222222222222222222222222222222\"\ncontroller_endpoint = \"https://lane.example\"\ncontroller_quic_endpoint = \"lane.example:8443\"\ncontroller_server_name = \"lane.example\""
            ),
        ];
        for contents in cases {
            std::fs::write(&path, &contents).unwrap();
            let result = Command::new(&go)
                .args(["config", "validate", "-config"])
                .arg(&path)
                .output()
                .unwrap();
            assert_eq!(
                Config::parse(&contents).is_ok(),
                result.status.success(),
                "{contents}\n{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}
