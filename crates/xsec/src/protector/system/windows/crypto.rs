use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{XSecError, XSecResult};

const MAGIC: &[u8; 6] = b"XSecSP";
const ENVELOPE_VERSION: u16 = 2;
const KEY_SIZE: usize = 32;
const IDENTITY_SIZE: usize = 32;
const CHALLENGE_SIZE: usize = 16;
const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KDF_INFO: &[u8] = b"xsec:windows-hello:kek";
const HEADER_SIZE: usize =
    MAGIC.len() + 2 + IDENTITY_SIZE + CHALLENGE_SIZE + SALT_SIZE + NONCE_SIZE;
const PAYLOAD_SIZE: usize = HEADER_SIZE + KEY_SIZE + TAG_SIZE;

type Identity = [u8; IDENTITY_SIZE];

pub(super) struct Challenge([u8; CHALLENGE_SIZE]);

impl Challenge {
    pub(super) fn random() -> XSecResult<Self> {
        let mut challenge = Self([0; CHALLENGE_SIZE]);
        getrandom::fill(&mut challenge.0).map_err(|_| XSecError::Crypto)?;
        Ok(challenge)
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(PartialEq, Eq)]
pub(super) struct WindowsHelloPrf(Zeroizing<[u8; KEY_SIZE]>);

impl WindowsHelloPrf {
    pub(super) fn from_signature(signature: &[u8]) -> Self {
        Self(Zeroizing::new(Sha256::digest(signature).into()))
    }
}

pub(super) struct SystemEnvelope<'a> {
    identity: &'a Identity,
    challenge: &'a [u8],
    salt: &'a [u8],
    nonce: &'a [u8],
    header: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> SystemEnvelope<'a> {
    pub(super) fn parse(payload: &'a [u8], expected_identity: &Identity) -> XSecResult<Self> {
        if payload.len() != PAYLOAD_SIZE {
            return Err(XSecError::Corrupted);
        }
        if payload.get(..MAGIC.len()) != Some(MAGIC) {
            return Err(XSecError::Corrupted);
        }
        if read_u16(payload, MAGIC.len())? != ENVELOPE_VERSION {
            return Err(XSecError::UnsupportedVersion);
        }

        let identity_start = MAGIC.len() + 2;
        let identity_end = identity_start + IDENTITY_SIZE;
        let identity = payload
            .get(identity_start..identity_end)
            .ok_or(XSecError::Corrupted)?
            .try_into()
            .map_err(|_| XSecError::Corrupted)?;
        if identity != expected_identity {
            return Err(XSecError::SystemKeyInvalidated);
        }

        let challenge_start = identity_end;
        let challenge_end = challenge_start + CHALLENGE_SIZE;
        let salt_start = challenge_end;
        let salt_end = salt_start + SALT_SIZE;
        let nonce_start = salt_end;
        let nonce_end = nonce_start + NONCE_SIZE;

        Ok(Self {
            identity,
            challenge: &payload[challenge_start..challenge_end],
            salt: &payload[salt_start..salt_end],
            nonce: &payload[nonce_start..nonce_end],
            header: &payload[..HEADER_SIZE],
            ciphertext: &payload[HEADER_SIZE..],
        })
    }

    pub(super) fn challenge(&self) -> &[u8] {
        self.challenge
    }

    pub(super) fn open(&self, prf: &WindowsHelloPrf) -> XSecResult<SecretBox<[u8; KEY_SIZE]>> {
        let kek = derive_kek(prf, self.salt, self.identity)?;
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| XSecError::Crypto)?;
        let nonce = Nonce::try_from(self.nonce).map_err(|_| XSecError::Corrupted)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: self.ciphertext,
                        aad: self.header,
                    },
                )
                .map_err(|_| XSecError::AuthenticationFailed)?,
        );
        if plaintext.len() != KEY_SIZE {
            return Err(XSecError::Corrupted);
        }

        let mut key = Box::new([0; KEY_SIZE]);
        key.copy_from_slice(&plaintext);
        Ok(SecretBox::new(key))
    }
}

pub(super) fn seal_key(
    key: &SecretBox<[u8; KEY_SIZE]>,
    identity: &Identity,
    challenge: &Challenge,
    prf: &WindowsHelloPrf,
) -> XSecResult<Vec<u8>> {
    let mut salt = [0; SALT_SIZE];
    let mut nonce = [0; NONCE_SIZE];
    getrandom::fill(&mut salt).map_err(|_| XSecError::Crypto)?;
    getrandom::fill(&mut nonce).map_err(|_| XSecError::Crypto)?;

    let mut envelope = Vec::with_capacity(PAYLOAD_SIZE);
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    envelope.extend_from_slice(identity);
    envelope.extend_from_slice(challenge.as_bytes());
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce);

    let kek = derive_kek(prf, &salt, identity)?;
    let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| XSecError::Crypto)?;
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| XSecError::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: key.expose_secret(),
                aad: &envelope,
            },
        )
        .map_err(|_| XSecError::Crypto)?;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn derive_kek(
    prf: &WindowsHelloPrf,
    salt: &[u8],
    identity: &Identity,
) -> XSecResult<Zeroizing<[u8; KEY_SIZE]>> {
    let mut kek = Zeroizing::new([0; KEY_SIZE]);
    Hkdf::<Sha256>::new(Some(salt), &prf.0[..])
        .expand_multi_info(&[KDF_INFO, identity], kek.as_mut())
        .map_err(|_| XSecError::Crypto)?;
    Ok(kek)
}

fn read_u16(payload: &[u8], offset: usize) -> XSecResult<u16> {
    let end = offset.checked_add(2).ok_or(XSecError::Corrupted)?;
    Ok(u16::from_be_bytes(
        payload
            .get(offset..end)
            .ok_or(XSecError::Corrupted)?
            .try_into()
            .map_err(|_| XSecError::Corrupted)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protector::system::hash_identity;

    const IDENTITY_OFFSET: usize = MAGIC.len() + 2;
    const CHALLENGE_OFFSET: usize = IDENTITY_OFFSET + IDENTITY_SIZE;
    const SALT_OFFSET: usize = CHALLENGE_OFFSET + CHALLENGE_SIZE;
    const NONCE_OFFSET: usize = SALT_OFFSET + SALT_SIZE;

    fn fixture() -> (
        SecretBox<[u8; KEY_SIZE]>,
        Identity,
        Challenge,
        WindowsHelloPrf,
    ) {
        (
            SecretBox::new(Box::new([9; KEY_SIZE])),
            hash_identity("test-account"),
            Challenge([4; CHALLENGE_SIZE]),
            WindowsHelloPrf::from_signature(b"stable-windows-hello-signature"),
        )
    }

    #[test]
    fn envelope_round_trip() {
        let (key, identity, challenge, prf) = fixture();
        let payload = seal_key(&key, &identity, &challenge, &prf).unwrap();
        let envelope = SystemEnvelope::parse(&payload, &identity).unwrap();
        let opened = envelope.open(&prf).unwrap();

        assert_eq!(opened.expose_secret(), key.expose_secret());
        assert_eq!(envelope.challenge(), challenge.as_bytes());
    }

    #[test]
    fn wrong_signature_cannot_open_envelope() {
        let (key, identity, challenge, prf) = fixture();
        let payload = seal_key(&key, &identity, &challenge, &prf).unwrap();
        let envelope = SystemEnvelope::parse(&payload, &identity).unwrap();
        let wrong_prf = WindowsHelloPrf::from_signature(b"attacker-controlled-signature");

        assert!(matches!(
            envelope.open(&wrong_prf),
            Err(XSecError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_identity_is_rejected_before_opening() {
        let (key, identity, challenge, prf) = fixture();
        let payload = seal_key(&key, &identity, &challenge, &prf).unwrap();

        assert!(matches!(
            SystemEnvelope::parse(&payload, &hash_identity("another-account")),
            Err(XSecError::SystemKeyInvalidated)
        ));
    }

    #[test]
    fn authenticated_fields_reject_tampering() {
        let (key, identity, challenge, prf) = fixture();
        let payload = seal_key(&key, &identity, &challenge, &prf).unwrap();

        for offset in [
            CHALLENGE_OFFSET,
            SALT_OFFSET,
            NONCE_OFFSET,
            HEADER_SIZE,
            PAYLOAD_SIZE - 1,
        ] {
            let mut tampered = payload.clone();
            tampered[offset] ^= 1;
            let envelope = SystemEnvelope::parse(&tampered, &identity).unwrap();
            assert!(
                matches!(envelope.open(&prf), Err(XSecError::AuthenticationFailed)),
                "tampering at offset {offset} was accepted"
            );
        }
    }

    #[test]
    fn parser_rejects_invalid_framing_and_version() {
        let (key, identity, challenge, prf) = fixture();
        let payload = seal_key(&key, &identity, &challenge, &prf).unwrap();

        assert!(matches!(
            SystemEnvelope::parse(&payload[..payload.len() - 1], &identity),
            Err(XSecError::Corrupted)
        ));

        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(matches!(
            SystemEnvelope::parse(&trailing, &identity),
            Err(XSecError::Corrupted)
        ));

        let mut wrong_magic = payload.clone();
        wrong_magic[0] ^= 1;
        assert!(matches!(
            SystemEnvelope::parse(&wrong_magic, &identity),
            Err(XSecError::Corrupted)
        ));

        let mut wrong_identity = payload.clone();
        wrong_identity[IDENTITY_OFFSET] ^= 1;
        assert!(matches!(
            SystemEnvelope::parse(&wrong_identity, &identity),
            Err(XSecError::SystemKeyInvalidated)
        ));

        let mut wrong_version = payload;
        wrong_version[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&3u16.to_be_bytes());
        assert!(matches!(
            SystemEnvelope::parse(&wrong_version, &identity),
            Err(XSecError::UnsupportedVersion)
        ));
    }

    #[test]
    fn each_seal_uses_fresh_salt_and_nonce() {
        let (key, identity, challenge, prf) = fixture();
        let first = seal_key(&key, &identity, &challenge, &prf).unwrap();
        let second = seal_key(&key, &identity, &challenge, &prf).unwrap();

        assert_ne!(
            &first[SALT_OFFSET..SALT_OFFSET + SALT_SIZE],
            &second[SALT_OFFSET..SALT_OFFSET + SALT_SIZE]
        );
        assert_ne!(
            &first[NONCE_OFFSET..NONCE_OFFSET + NONCE_SIZE],
            &second[NONCE_OFFSET..NONCE_OFFSET + NONCE_SIZE]
        );
    }
}
