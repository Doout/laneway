//! AES-256-GCM envelope interoperable with the Connector bootstrap server.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const HEADER_SIZE: usize = 9;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const BAD_ENVELOPE: &str = "bootstrap secret: invalid key or payload";

fn valid_token(token: &[u8]) -> bool {
    !token.is_empty()
        && token.len() <= super::MAX_TOKEN
        && !token
            .iter()
            .any(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

pub(super) fn seal(token: &[u8], now: i64, expires_at: i64) -> Result<(Zeroizing<String>, String)> {
    ensure!(
        valid_token(token),
        "bootstrap secret: setup token is invalid"
    );
    ensure!(
        now < expires_at && expires_at <= now.saturating_add(600),
        "bootstrap secret: expiry must be in (0,10m0s]"
    );
    let rng = SystemRandom::new();
    let mut key_bytes = Zeroizing::new([0_u8; 32]);
    let mut nonce = [0_u8; NONCE_SIZE];
    rng.fill(&mut *key_bytes)
        .map_err(|_| anyhow::anyhow!("bootstrap secret: generate key"))?;
    rng.fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("bootstrap secret: generate nonce"))?;
    let key =
        UnboundKey::new(&AES_256_GCM, &*key_bytes).map_err(|_| anyhow::anyhow!(BAD_ENVELOPE))?;
    let mut header = [VERSION; HEADER_SIZE];
    header[1..].copy_from_slice(&expires_at.to_be_bytes());
    let mut ciphertext = Zeroizing::new(token.to_vec());
    let tag = LessSafeKey::new(key)
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(header),
            &mut ciphertext,
        )
        .map_err(|_| anyhow::anyhow!("bootstrap secret: seal payload"))?;
    let mut envelope = Vec::with_capacity(HEADER_SIZE + NONCE_SIZE + ciphertext.len() + TAG_SIZE);
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    envelope.extend_from_slice(tag.as_ref());
    Ok((
        Zeroizing::new(URL_SAFE_NO_PAD.encode(key_bytes.as_slice())),
        URL_SAFE_NO_PAD.encode(envelope),
    ))
}

pub(super) fn open(key: &str, envelope: &str, now: i64) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        envelope.len() <= super::MAX_ENVELOPE && key.len() == 43,
        "{BAD_ENVELOPE}"
    );
    let key_bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(key).context(BAD_ENVELOPE)?);
    let key =
        UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| anyhow::anyhow!(BAD_ENVELOPE))?;
    let envelope = URL_SAFE_NO_PAD.decode(envelope).context(BAD_ENVELOPE)?;
    ensure!(
        envelope.len() > HEADER_SIZE + NONCE_SIZE + TAG_SIZE && envelope[0] == VERSION,
        "{BAD_ENVELOPE}"
    );
    let header = &envelope[..HEADER_SIZE];
    let nonce = Nonce::try_assume_unique_for_key(&envelope[HEADER_SIZE..HEADER_SIZE + NONCE_SIZE])
        .map_err(|_| anyhow::anyhow!(BAD_ENVELOPE))?;
    let mut contents = Zeroizing::new(envelope[HEADER_SIZE + NONCE_SIZE..].to_vec());
    let plaintext = LessSafeKey::new(key)
        .open_in_place(nonce, Aad::from(header), &mut contents)
        .map_err(|_| anyhow::anyhow!(BAD_ENVELOPE))?;
    ensure!(valid_token(plaintext), "{BAD_ENVELOPE}");
    let length = plaintext.len();
    let expiration = i64::from_be_bytes(header[1..].try_into().expect("fixed length header"));
    ensure!(expiration > now, "bootstrap secret: payload has expired");
    contents.truncate(length);
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_go_wire_format_and_authenticates_expiry() {
        // Generated with Go crypto/aes and cipher.NewGCM with fixed fixture material.
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let envelope = "AQAAAAB3NZQ8ICEiIyQlJicoKSoroU6XXhj9aXo3Giu2tW2GnGOj1GI9PdOyUdayeHOm4y0";
        assert_eq!(
            open(key, envelope, 2_000_000_000).unwrap().as_slice(),
            b"st1.test-fixture"
        );
        assert!(
            open(key, envelope, 2_000_000_060)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
        let mut changed = URL_SAFE_NO_PAD.decode(envelope).unwrap();
        changed[8] ^= 1;
        assert_eq!(
            open(key, &URL_SAFE_NO_PAD.encode(changed), 2_000_000_000)
                .unwrap_err()
                .to_string(),
            BAD_ENVELOPE
        );
    }

    #[test]
    fn sealing_preserves_bounds_and_round_trips() {
        let (key, envelope) = seal(b"st1.test", 100, 700).unwrap();
        assert_eq!(open(&key, &envelope, 699).unwrap().as_slice(), b"st1.test");
        assert!(seal(b"st1. test", 100, 700).is_err());
        assert!(seal(b"st1.test", 100, 701).is_err());
        assert!(seal(&[b'A'; super::super::MAX_TOKEN + 1], 100, 700).is_err());
    }
}
