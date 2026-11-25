#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod enrollment;

#[cfg(target_os = "linux")]
mod acl_admin;
mod backup;
#[cfg(target_os = "linux")]
mod policy;
mod restore;
mod schema;
#[cfg(target_os = "linux")]
mod serve;
#[cfg(target_os = "linux")]
mod serve_enrollment;
#[cfg(target_os = "linux")]
mod serve_quic;
#[cfg(target_os = "linux")]
mod snapshots;
#[cfg(target_os = "linux")]
mod startup;
#[cfg(target_os = "linux")]
mod store;

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail, ensure};
use laneway_config::Config;

static CANCELED: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("laneway-controller: {error:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let mut config = PathBuf::from("/etc/laneway/controller.toml");
    let mut backup_path = None;
    let mut restore_path = None;
    let mut prepare_startup = false;
    let mut serve_readonly = false;
    let mut serve_enrollment = false;
    let mut serve_full = false;
    let mut diagnostics = None;
    while let Some(flag) = args.next() {
        match flag.to_str() {
            Some("-config" | "--config") => config = required_path(args.next(), "-config")?,
            Some("-backup" | "--backup") => {
                backup_path = Some(required_path(args.next(), "-backup")?);
            }
            Some("-restore" | "--restore") => {
                restore_path = Some(required_path(args.next(), "-restore")?);
            }
            Some("-prepare-startup" | "--prepare-startup") => prepare_startup = true,
            Some("-serve-readonly" | "--serve-readonly") => serve_readonly = true,
            Some("-serve-enrollment-candidate" | "--serve-enrollment-candidate") => {
                serve_enrollment = true
            }
            Some("-serve-controller-candidate" | "--serve-controller-candidate") => {
                serve_full = true
            }
            Some("-diagnostics" | "--diagnostics") => {
                diagnostics = Some(
                    args.next()
                        .context("-diagnostics requires an address")?
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("diagnostics address must be UTF-8"))?,
                );
            }
            Some("-h" | "--help") => {
                println!(
                    "usage: laneway-controller [-config FILE] (-backup DESTINATION | -restore SOURCE | -prepare-startup | -serve-readonly | -serve-enrollment-candidate | -serve-controller-candidate) [-diagnostics HOST:PORT]"
                );
                return Ok(());
            }
            _ => bail!(
                "unsupported controller candidate option: {}",
                flag.to_string_lossy()
            ),
        }
    }
    match usize::from(backup_path.is_some())
        + usize::from(restore_path.is_some())
        + usize::from(prepare_startup)
        + usize::from(serve_readonly)
        + usize::from(serve_enrollment)
        + usize::from(serve_full)
    {
        0 => bail!("controller candidate requires an explicit operation"),
        1 => {}
        _ => {
            bail!("controller candidate operations are mutually exclusive")
        }
    }
    ensure!(
        serve_readonly || serve_enrollment || serve_full || diagnostics.is_none(),
        "-diagnostics requires a controller serving mode"
    );
    if serve_readonly || serve_enrollment || serve_full {
        #[cfg(target_os = "linux")]
        return serve::run(
            &config,
            diagnostics.as_deref(),
            serve_enrollment || serve_full,
            serve_full,
        );
        #[cfg(not(target_os = "linux"))]
        bail!("the controller serving candidate requires Linux");
    }
    if prepare_startup {
        #[cfg(target_os = "linux")]
        return startup::prepare(&config);
        #[cfg(not(target_os = "linux"))]
        bail!("startup preparation requires Linux lifecycle locking");
    }
    let settings = Config::load(&config)?;
    ensure!(
        settings.mode == "controller",
        "configuration mode is {:?}, want \"controller\"",
        settings.mode
    );
    let database = Path::new(&settings.controller.database);
    ctrlc::set_handler(|| CANCELED.store(true, Ordering::Relaxed))
        .context("install maintenance cancellation handler")?;

    if let Some(destination) = backup_path {
        backup::database(database, &destination, &CANCELED)?;
        println!(
            "controller database backup written to {}",
            destination.display()
        );
    } else if let Some(source) = restore_path {
        restore::database(&source, database, &CANCELED)?;
        println!(
            "controller database restored from {}; start the controller to apply compatible migrations",
            source.display()
        );
    }
    Ok(())
}

fn required_path(value: Option<std::ffi::OsString>, flag: &str) -> Result<PathBuf> {
    let Some(value) = value else {
        bail!("{flag} requires a path");
    };
    if value.is_empty() {
        bail!("{flag} requires a nonempty path");
    }
    Ok(PathBuf::from(value))
}
