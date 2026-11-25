pub(crate) const VERSION: &str = match option_env!("LANEWAY_CLI_RELEASE_VERSION") {
    Some(value) => value,
    None => match option_env!("LANEWAY_VERSION") {
        Some(value) => value,
        None => env!("CARGO_PKG_VERSION"),
    },
};
