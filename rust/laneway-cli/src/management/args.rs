use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::Id;

const CONNECT: &[&str] = &[
    "controller",
    "ca",
    "server-name",
    "controller-network-id",
    "controller-service-id",
];

pub(super) struct Flags<'a> {
    values: BTreeMap<&'a str, &'a OsStr>,
}

impl<'a> Flags<'a> {
    pub(super) fn parse(
        args: &'a [OsString],
        fields: &[&str],
        booleans: &[&str],
        node: bool,
    ) -> Result<(Self, &'a [OsString])> {
        Self::parse_inner(args, fields, booleans, Some(node))
    }

    pub(super) fn local(
        args: &'a [OsString],
        fields: &[&str],
        booleans: &[&str],
    ) -> Result<(Self, &'a [OsString])> {
        Self::parse_inner(args, fields, booleans, None)
    }

    fn parse_inner(
        args: &'a [OsString],
        fields: &[&str],
        booleans: &[&str],
        node: Option<bool>,
    ) -> Result<(Self, &'a [OsString])> {
        let mut values = BTreeMap::new();
        let mut rest = args;
        while let [next, tail @ ..] = rest {
            let raw = next.as_os_str().as_bytes();
            let flag = raw.strip_prefix(b"--").or_else(|| raw.strip_prefix(b"-"));
            let Some(flag) = flag.filter(|flag| !flag.is_empty()) else {
                if raw == b"--" {
                    rest = tail;
                }
                break;
            };
            let separator = flag.iter().position(|byte| *byte == b'=');
            let (flag, inline) = match separator {
                Some(index) => (&flag[..index], Some(OsStr::from_bytes(&flag[index + 1..]))),
                None => (flag, None),
            };
            let flag =
                std::str::from_utf8(flag).context("controller option must be valid UTF-8")?;
            let boolean = booleans.contains(&flag);
            ensure!(
                boolean
                    || fields.contains(&flag)
                    || node.is_some_and(|node| CONNECT.contains(&flag)
                        || if node {
                            matches!(flag, "cert" | "key")
                        } else {
                            flag == "admin-token-file"
                        }),
                "flag provided but not defined: --{flag}"
            );
            let (value, tail) = match (inline, boolean, tail) {
                (Some(value), _, tail) => (value, tail),
                (None, true, tail) => (OsStr::new("true"), tail),
                (None, false, [value, tail @ ..]) => (value.as_os_str(), tail),
                _ => bail!("flag needs an argument: --{flag}"),
            };
            if boolean {
                parse_bool(value.to_str().context("boolean must be valid UTF-8")?)
                    .with_context(|| format!("invalid value for --{flag}"))?;
            }
            values.insert(flag, value);
            rest = tail;
        }
        Ok((Self { values }, rest))
    }

    pub(super) fn contains(&self, flag: &str) -> bool {
        self.values.contains_key(flag)
    }

    pub(super) fn fallback(&mut self, key: &'static str, value: &'a str) {
        self.values.entry(key).or_insert_with(|| OsStr::new(value));
    }

    pub(super) fn text(&self, flag: &str) -> Result<&'a str> {
        self.text_or(flag, "")
    }

    pub(super) fn text_or(&self, flag: &str, default: &'a str) -> Result<&'a str> {
        self.values.get(flag).map_or(Ok(default), |value| {
            value
                .to_str()
                .with_context(|| format!("--{flag} must be valid UTF-8"))
        })
    }

    pub(super) fn required(&self, flag: &str) -> Result<&'a str> {
        let value = self.text(flag)?;
        ensure!(!value.trim().is_empty(), "--{flag} is required");
        Ok(value)
    }

    pub(super) fn path(&self, flag: &str, default: &'a str) -> &'a Path {
        Path::new(
            self.values
                .get(flag)
                .copied()
                .unwrap_or(OsStr::new(default)),
        )
    }

    pub(super) fn id(&self, flag: &str) -> Result<Id> {
        self.required(flag)?
            .parse()
            .with_context(|| format!("--{flag}"))
    }

    pub(super) fn boolean(&self, flag: &str, default: bool) -> Result<bool> {
        parse_bool(self.text_or(flag, if default { "true" } else { "false" })?)
    }

    pub(super) fn enum_value(
        &self,
        flag: &str,
        default: &'a str,
        choices: &[&str],
    ) -> Result<&'a str> {
        let value = self.text_or(flag, default)?;
        ensure!(
            choices.contains(&value),
            "--{flag} must be {}",
            choices.join(" or ")
        );
        Ok(value)
    }

    pub(super) fn number(&self, flag: &str, default: &'a str) -> Result<u32> {
        let value = self.text_or(flag, default)?;
        let value = value.strip_prefix('+').unwrap_or(value);
        let (radix, digits) = if let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            (16, hex)
        } else if let Some(binary) = value
            .strip_prefix("0b")
            .or_else(|| value.strip_prefix("0B"))
        {
            (2, binary)
        } else if let Some(octal) = value
            .strip_prefix("0o")
            .or_else(|| value.strip_prefix("0O"))
        {
            (8, octal)
        } else if value.len() > 1 && value.starts_with('0') {
            (8, value)
        } else {
            (10, value)
        };
        u32::from_str_radix(digits, radix).with_context(|| format!("invalid --{flag} value"))
    }

    pub(super) fn limit(&self) -> Result<u32> {
        let limit = self.number("limit", "100")?;
        ensure!(
            (1..=1000).contains(&limit),
            "--limit must be from 1 through 1000"
        );
        Ok(limit)
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "1" | "t" | "T" | "true" | "True" | "TRUE" => Ok(true),
        "0" | "f" | "F" | "false" | "False" | "FALSE" => Ok(false),
        _ => bail!("invalid boolean {value:?}"),
    }
}
