use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(super) enum Purpose {
    Client,
    Registration,
    Authorization,
}

impl Purpose {
    fn labels(self) -> (&'static str, &'static [u8]) {
        match self {
            Self::Client => (
                "lnw_client_secret_v1",
                b"laneway-application-client_secret-v1\0",
            ),
            Self::Registration => (
                "lnw_registration_v1",
                b"laneway-application-registration_code-v1\0",
            ),
            Self::Authorization => (
                "lnw_authorization_v1",
                b"laneway-application-authorization_code-v1\0",
            ),
        }
    }

    fn digest(self, id: Id, text: &str) -> [u8; 32] {
        Sha256::new()
            .chain_update(self.labels().1)
            .chain_update(id.as_bytes())
            .chain_update(text.as_bytes())
            .finalize()
            .into()
    }
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0; N]);
    getrandom::fill(out.as_mut_slice())
        .map_err(|_| anyhow::anyhow!("application randomness unavailable"))?;
    Ok(out)
}

pub(super) fn id() -> Result<Id> {
    Ok(Id::new(*random::<16>()?)?)
}

pub(super) fn new_secret(purpose: Purpose, id: Id) -> Result<(Zeroizing<String>, [u8; 32])> {
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(random::<32>()?.as_slice()));
    let digest = purpose.digest(id, &encoded);
    Ok((
        Zeroizing::new(format!("{}.{id}.{}", purpose.labels().0, encoded.as_str())),
        digest,
    ))
}

pub(super) fn parse_secret(purpose: Purpose, token: &str) -> Option<(Id, [u8; 32])> {
    let suffix = token.strip_prefix(purpose.labels().0)?.strip_prefix('.')?;
    let (id, encoded) = suffix.split_once('.')?;
    let id = id.parse::<Id>().ok()?;
    challenge_valid(encoded).then(|| (id, purpose.digest(id, encoded)))
}

pub(super) fn challenge_valid(encoded: &str) -> bool {
    let mut raw = Zeroizing::new([0u8; 32]);
    encoded.len() == 43 && URL_SAFE_NO_PAD.decode_slice(encoded, &mut *raw) == Ok(raw.len())
}

pub(super) fn matches_pkce(challenge: &str, verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && bool::from(
            URL_SAFE_NO_PAD
                .encode(Sha256::digest(verifier.as_bytes()))
                .as_bytes()
                .ct_eq(challenge.as_bytes()),
        )
}
