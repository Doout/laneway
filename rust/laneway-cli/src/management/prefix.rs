use std::{fmt, net::IpAddr, str::FromStr};

use anyhow::{Context, Result, ensure};

#[derive(Debug, Clone, Copy)]
pub(super) struct Prefix {
    pub(super) addr: IpAddr,
    pub(super) bits: u8,
}

impl Prefix {
    pub(super) fn assigned(value: &str) -> Result<Self> {
        if let Ok(addr) = value.parse::<IpAddr>() {
            ensure!(
                !mapped(addr),
                "route destination must not be IPv4-mapped IPv6"
            );
            return Ok(Self {
                addr,
                bits: width(addr),
            });
        }
        let prefix: Self = value.parse()?;
        ensure!(
            prefix.bits > 0,
            "--to must be an IP address or canonical non-default prefix"
        );
        Ok(prefix)
    }

    pub(super) fn octets(self) -> Vec<u8> {
        match self.addr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        }
    }
}

impl FromStr for Prefix {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (addr, bits) = value
            .split_once('/')
            .context("expected a canonical IP prefix")?;
        let addr = addr.parse()?;
        let bits = bits.parse::<u8>()?;
        let size = width(addr);
        ensure!(
            bits <= size && !mapped(addr),
            "expected a canonical IP prefix"
        );
        let mask = if bits == 0 {
            0
        } else {
            u128::MAX << (size - bits)
        };
        let numeric = match addr {
            IpAddr::V4(addr) => u128::from(u32::from(addr)),
            IpAddr::V6(addr) => u128::from(addr),
        };
        ensure!(numeric & mask == numeric, "expected a canonical IP prefix");
        Ok(Self { addr, bits })
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{}/{}", self.addr, self.bits)
    }
}

fn width(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn mapped(addr: IpAddr) -> bool {
    matches!(addr, IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some())
}
