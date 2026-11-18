//! Names that may be preserved when renewing an authenticated service leaf.
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

/// DNS name or IP address taken from a trusted service certificate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Name {
    /// Case-normalized DNS name.
    Dns(String),
    /// Exact IP address.
    Ip(IpAddr),
}

/// Extract the non-identity SAN entries for a service replacement. The caller
/// must separately verify the certificate's trust, validity and SPIFFE identity.
pub fn from_der(der: &[u8]) -> Result<BTreeSet<Name>, crate::Error> {
    use crate::Error::InvalidCertificate as Invalid;
    let (remaining, cert) = parse_x509_certificate(der).map_err(|_| Invalid)?;
    if !remaining.is_empty() {
        return Err(Invalid);
    }
    let san = cert
        .subject_alternative_name()
        .map_err(|_| Invalid)?
        .ok_or(Invalid)?;
    let mut names = BTreeSet::new();
    let mut uris = 0;
    for value in &san.value.general_names {
        let name = match value {
            GeneralName::URI(_) => {
                uris += 1;
                continue;
            }
            GeneralName::DNSName(name) if !name.is_empty() && !name.contains('*') => {
                Name::Dns(name.to_ascii_lowercase())
            }
            GeneralName::IPAddress(raw) if raw.len() == 4 => {
                Name::Ip(Ipv4Addr::from(<[u8; 4]>::try_from(*raw).map_err(|_| Invalid)?).into())
            }
            GeneralName::IPAddress(raw) if raw.len() == 16 => {
                Name::Ip(Ipv6Addr::from(<[u8; 16]>::try_from(*raw).map_err(|_| Invalid)?).into())
            }
            _ => return Err(Invalid),
        };
        if names.len() >= 32 || !names.insert(name) {
            return Err(Invalid);
        }
    }
    if uris != 1 {
        return Err(Invalid);
    }
    Ok(names)
}
