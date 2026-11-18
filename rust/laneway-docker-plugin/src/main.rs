#[cfg(target_os = "linux")]
use std::{env, path::PathBuf, sync::Arc};

fn main() {
    if let Err(error) = run() {
        eprintln!("laneway-docker-plugin: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), &'static str> {
    Err("the managed Docker network plugin requires Linux")
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use laneway_docker_plugin::{Driver, LinuxBackend, Store, serve_until};
    use tokio::signal::unix::{SignalKind, signal};

    let version = option_env!("LANEWAY_PRODUCT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    let mut args = env::args_os().skip(1);
    let mut socket = PathBuf::from("/run/docker/plugins/laneway.sock");
    let mut state = PathBuf::from("/var/lib/laneway-docker-plugin/state-v1.json");
    let mut authorization =
        PathBuf::from("/var/lib/laneway-docker-plugin/controller-authorization-v1.json");
    let mut tunnel = "lane0".to_owned();
    while let Some(raw) = args.next() {
        let option = raw.to_str().ok_or("plugin arguments must be UTF-8")?;
        let (option, value) = option
            .split_once('=')
            .map_or((option, None), |(k, v)| (k, Some(v)));
        let name = option
            .strip_prefix("--")
            .or_else(|| option.strip_prefix('-'))
            .ok_or("the plugin accepts named flags only")?;
        if name == "version" && value.is_none() && args.next().is_none() {
            println!("{version}");
            return Ok(());
        }
        if name == "help" && value.is_none() && args.next().is_none() {
            println!(
                "Usage: laneway-docker-plugin [-socket PATH] [-state PATH] [-authorization PATH] [-tunnel-interface IFACE]"
            );
            return Ok(());
        }
        let value = value
            .map(Into::into)
            .or_else(|| args.next())
            .ok_or("missing plugin flag value")?;
        match name {
            "socket" => socket = value.into(),
            "state" => state = value.into(),
            "authorization" => authorization = value.into(),
            "tunnel-interface" => {
                tunnel = value
                    .into_string()
                    .map_err(|_| "invalid tunnel interface")?
            }
            _ => return Err(format!("unknown plugin flag {name}").into()),
        }
    }
    if [&socket, &state, &authorization]
        .into_iter()
        .any(|path| !path.is_absolute())
        || socket == state
        || socket == authorization
        || state == authorization
    {
        return Err(
            "plugin socket, state, and authorization must be distinct absolute paths".into(),
        );
    }
    let driver = Arc::new(Driver::new(
        Store::open(state)?,
        LinuxBackend::new(&tunnel)?,
        authorization,
        version.to_owned(),
    ));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut term = signal(SignalKind::terminate())?;
            let mut interrupt = signal(SignalKind::interrupt())?;
            serve_until(&socket, driver, async {
                tokio::select! { _ = term.recv() => (), _ = interrupt.recv() => () }
            })
            .await
        })?;
    Ok(())
}
