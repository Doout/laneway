use std::{
    ffi::OsString,
    io::{self, Write},
};

use anyhow::{Result, bail};
use laneway_protocol::{ID_LEN, Id};

mod issue;
mod pki;

pub(crate) use pki::parse_duration;

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    match args {
        [command, ..] if command == "id" => {
            writeln!(io::stdout().lock(), "{}", random_id()?)?;
            Ok(())
        }
        [command, action, rest @ ..] if command == "pki" && action == "init" => {
            pki::init(rest, io::stdout().lock())
        }
        [command, action, ..] if command == "pki" && action == "verify-authority" => {
            issue::verify(args)
        }
        [command, action, ..] if command == "pki" && is_issuer_command(action) => issue::run(args),
        _ => bail!("unknown utility command"),
    }
}

fn random_id() -> Result<Id> {
    loop {
        let mut bytes = [0; ID_LEN];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("generate Laneway ID: {error}"))?;
        if let Ok(id) = Id::new(bytes) {
            return Ok(id);
        }
    }
}

pub(crate) fn is_issuer_command(action: &std::ffi::OsStr) -> bool {
    matches!(
        action.to_str(),
        Some("verify-authority" | "intermediate" | "node" | "relay" | "controller")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_id_formats_as_laneway_wire_id() {
        let first = random_id().unwrap();
        let second = random_id().unwrap();
        assert_ne!(first, second);
        assert_eq!(first.to_string().len(), ID_LEN * 2);
        assert_eq!(first.to_string().parse::<Id>().unwrap(), first);
    }
}
