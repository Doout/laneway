#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1).peekable();
    if matches!(
        args.peek().map(String::as_str),
        Some("--version" | "-version")
    ) && args.len() == 1
    {
        println!(
            "{}",
            option_env!("LANEWAY_PRODUCT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        );
        return std::process::ExitCode::SUCCESS;
    }
    match lanewayd_rs::fleet_update::run(args).await {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(error) => {
            // Errors may include credential file paths or remote URLs. The
            // top-level context is intentionally static and locally actionable.
            eprintln!("managed update stopped: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("managed Rust node updates require Linux");
    std::process::ExitCode::FAILURE
}
