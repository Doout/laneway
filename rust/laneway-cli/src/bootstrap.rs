//! Public Web PKI discovery and verification of advertised release artifacts.

mod http;
mod metadata;

use std::{ffi::OsString, io, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

pub(crate) use http::fetch;
pub(crate) use metadata::{Artifact, Metadata};
#[cfg(test)]
pub(crate) use metadata::{Controller, Trust};

const USAGE: &str = "Usage: laneway bootstrap <inspect|download> DOMAIN [--out PATH]";

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    let args = if args.first().is_some_and(|arg| arg == "bootstrap") {
        &args[1..]
    } else {
        args
    };
    if args
        .first()
        .is_some_and(|arg| arg == "--help" || arg == "-h")
    {
        println!("{USAGE}");
        return Ok(());
    }
    let Some((command, args)) = args.split_first() else {
        bail!("{USAGE}");
    };
    ensure!(command == "inspect" || command == "download", "{USAGE}");
    let Some(options) = options(args)? else {
        println!("{USAGE}");
        return Ok(());
    };
    ensure!(
        !options.authority.is_empty()
            && (command == "download")
                == options
                    .output
                    .as_ref()
                    .is_some_and(|p| !p.as_os_str().is_empty()),
        "bootstrap inspect requires DOMAIN; bootstrap download requires DOMAIN and --out PATH"
    );
    let metadata = fetch(&options.authority)?;
    let artifact = metadata.artifact_for_current_platform()?;
    if command == "inspect" {
        #[derive(Serialize)]
        struct Inspection<'a> {
            metadata: &'a Metadata,
            current_platform_artifact: &'a Artifact,
        }
        let stdout = io::stdout().lock();
        serde_json::to_writer_pretty(
            stdout,
            &Inspection {
                metadata: &metadata,
                current_platform_artifact: artifact,
            },
        )?;
        println!();
    } else {
        let output = options.output.context("missing artifact output path")?;
        http::download_artifact(artifact, &output)?;
        println!(
            "verified artifact {}/{} sha256={} path={}",
            artifact.os,
            artifact.arch,
            artifact.sha256,
            output.display()
        );
    }
    Ok(())
}

struct Options {
    authority: String,
    output: Option<PathBuf>,
}

fn options(args: &[OsString]) -> Result<Option<Options>> {
    let mut args = args.iter().peekable();
    let mut authority = None;
    let mut output = None;
    // Match Go's flag parser, which first consumes an optional leading domain.
    if args
        .peek()
        .is_some_and(|arg| !arg.is_empty() && !arg.to_string_lossy().starts_with('-'))
    {
        authority = args.next();
    }
    while let Some(arg) = args.peek() {
        let Some(flag) = arg.to_str() else {
            bail!("bootstrap arguments must use Unicode domain names and option names");
        };
        if !flag.starts_with('-') || flag == "-" {
            break;
        }
        args.next();
        match flag {
            "--" => break,
            "-h" | "--help" => return Ok(None),
            "--out" | "-out" => {
                output = Some(PathBuf::from(
                    args.next().context("missing value for --out")?,
                ))
            }
            _ => {
                let value = flag
                    .strip_prefix("--out=")
                    .or_else(|| flag.strip_prefix("-out="));
                match value {
                    Some(value) => output = Some(PathBuf::from(value)),
                    None => bail!("unrecognized bootstrap option {flag}"),
                }
            }
        }
    }
    if authority.is_none() {
        authority = args.next();
    }
    ensure!(args.next().is_none(), "{USAGE}");
    Ok(Some(Options {
        authority: authority
            .map(|arg| arg.to_str().context("bootstrap domain must be Unicode"))
            .transpose()?
            .unwrap_or_default()
            .to_owned(),
        output,
    }))
}
