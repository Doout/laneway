use std::{env, process::ExitCode};

fn main() -> ExitCode {
    if matches!(
        env::args_os().nth(1).as_deref().and_then(|s| s.to_str()),
        Some("--version" | "-version")
    ) && env::args_os().nth(2).is_none()
    {
        println!(
            "{}",
            option_env!("LANEWAY_PRODUCT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        );
        return ExitCode::SUCCESS;
    }
    laneway_healthcheck::run("laneway-healthcheck", env::args().skip(1))
}
