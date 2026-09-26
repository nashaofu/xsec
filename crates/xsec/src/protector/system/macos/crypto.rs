use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{XSecError, XSecResult};

const MAGIC: &[u8; 6] = b"XSecMP";
const WINDOWS_MAGIC: &[u8; 6] = b"XSecSP";
const LINUX_MAGIC: &[u8; 6] = b"XSecLP";
const ENVELOPE_VERSION: u16 = 1;
const KEY_SIZE: usize = 32;
const IDENTITY_SIZE: usize = 32;
const KEY_HASH_SIZE: usize = 32;
const PUBLIC_KEY_SIZE: usize = 65;
const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KDF_INFO: &[u8] = b"xsec:macos-secure-enclave:kek";
const HEADER_SIZE: usize =
    MAGIC.len() + 2 + IDENTITY_SIZE + KEY_HASH_SIZE + PUBLIC_KEY_SIZE + SALT_SIZE + NONCE_SIZE;
const PAYLOAD_SIZE: usize = HEADER_SIZE + KEY_SIZE + TAG_SIZE;

pub(super) type Identity = [u8; IDENTITY_SIZE];
pub(super) type PublicKey = [u8; PUBLIC_KEY_SIZE];
pub(super) type SharedSecret = Zeroizing<[u8; KEY_SIZE]>;

pub(super) struct MacosEnvelope<'a> {
    identity: &'a Identity,
    recipient_key_hash: &'a [u8; KEY_HASH_SIZE],
    ephemeral_public_key: &'a PublicKey,
    salt: &'a [u8; SALT_SIZE],
    nonce: &'a [u8; NONCE_SIZE],
    header: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> MacosEnvelope<'a> {
    pub(super) fn parse(payload: &'a [u8], expected_identity: &Identity) -> XSecResult<Self> {
        Self::parse_inner(payload, Some(expected_identity))
    }

    pub(super) fn parse_stored(payload: &'a [u8]) -> XSecResult<Self> {
        Self::parse_inner(payload, None)
    }

    fn parse_inner(payload: &'a [u8], expected_identity: Option<&Identity>) -> XSecResult<Self> {
        if matches!(
            payload.get(..MAGIC.len()),
            Some(value) if value == WINDOWS_MAGIC || value == LINUX_MAGIC
        ) {
            return Err(XSecError::IncompatibleSystemProtector);
        }
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
        let identity = array(payload, identity_start)?;
        if expected_identity.is_some_and(|expected| identity != expected) {
            return Err(XSecError::SystemKeyInvalidated);
        }

        let key_hash_start = identity_end;
        let key_hash_end = key_hash_start + KEY_HASH_SIZE;
        let public_key_start = key_hash_end;
        let public_key_end = public_key_start + PUBLIC_KEY_SIZE;
        let salt_start = public_key_end;
        let salt_end = salt_start + SALT_SIZE;
        let nonce_start = salt_end;
        let ephemeral_public_key = array(payload, public_key_start)?;
        if ephemeral_public_key[0] != 4 {
            return Err(XSecError::Corrupted);
        }

        Ok(Self {
            identity,
            recipient_key_hash: array(payload, key_hash_start)?,
            ephemeral_public_key,
            salt: array(payload, salt_start)?,
            nonce: array(payload, nonce_start)?,
            header: &payload[..HEADER_SIZE],
            ciphertext: &payload[HEADER_SIZE..],
        })
    }

    pub(super) fn identity(&self) -> &Identity {
        self.identity
    }

    pub(super) fn recipient_key_hash(&self) -> &[u8; KEY_HASH_SIZE] {
        self.recipient_key_hash
    }

    pub(super) fn ephemeral_public_key(&self) -> &PublicKey {
        self.ephemeral_public_key
    }

    pub(super) fn open(
        &self,
        shared_secret: &SharedSecret,
    ) -> XSecResult<SecretBox<[u8; KEY_SIZE]>> {
        let kek = derive_kek(
            shared_secret,
            self.salt,
            self.identity,
            self.recipient_key_hash,
        )?;
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| XSecError::Crypto)?;
        let nonce = Nonce::try_from(self.nonce.as_slice()).map_err(|_| XSecError::Corrupted)?;
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
    recipient_key_hash: &[u8; KEY_HASH_SIZE],
    ephemeral_public_key: &PublicKey,
    shared_secret: &SharedSecret,
) -> XSecResult<Vec<u8>> {
    let mut salt = [0; SALT_SIZE];
    let mut nonce = [0; NONCE_SIZE];
    getrandom::fill(&mut salt).map_err(|_| XSecError::Crypto)?;
    getrandom::fill(&mut nonce).map_err(|_| XSecError::Crypto)?;

    let mut envelope = Vec::with_capacity(PAYLOAD_SIZE);
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    envelope.extend_from_slice(identity);
    envelope.extend_from_slice(recipient_key_hash);
    envelope.extend_from_slice(ephemeral_public_key);
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce);

    let kek = derive_kek(shared_secret, &salt, identity, recipient_key_hash)?;
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
    shared_secret: &SharedSecret,
    salt: &[u8; SALT_SIZE],
    identity: &Identity,
    recipient_key_hash: &[u8; KEY_HASH_SIZE],
) -> XSecResult<Zeroizing<[u8; KEY_SIZE]>> {
    let mut kek = Zeroizing::new([0; KEY_SIZE]);
    Hkdf::<Sha256>::new(Some(salt), &shared_secret[..])
        .expand_multi_info(&[KDF_INFO, identity, recipient_key_hash], kek.as_mut())
        .map_err(|_| XSecError::Crypto)?;
    Ok(kek)
}

fn array<const N: usize>(payload: &[u8], offset: usize) -> XSecResult<&[u8; N]> {
    payload
        .get(offset..offset + N)
        .ok_or(XSecError::Corrupted)?
        .try_into()
        .map_err(|_| XSecError::Corrupted)
}

fn read_u16(payload: &[u8], offset: usize) -> XSecResult<u16> {
    Ok(u16::from_be_bytes(*array(payload, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protector::system::hash_identity;
    use secrecy::ExposeSecret;
    use sha2::{Digest, Sha256};

    const IDENTITY_OFFSET: usize = MAGIC.len() + 2;
    const KEY_HASH_OFFSET: usize = IDENTITY_OFFSET + IDENTITY_SIZE;
    const PUBLIC_KEY_OFFSET: usize = KEY_HASH_OFFSET + KEY_HASH_SIZE;
    const SALT_OFFSET: usize = PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE;
    const NONCE_OFFSET: usize = SALT_OFFSET + SALT_SIZE;

    fn fixture() -> (
        SecretBox<[u8; KEY_SIZE]>,
        Identity,
        [u8; KEY_HASH_SIZE],
        PublicKey,
        SharedSecret,
    ) {
        let mut public_key = [3; PUBLIC_KEY_SIZE];
        public_key[0] = 4;
        (
            SecretBox::new(Box::new([9; KEY_SIZE])),
            hash_identity("test-account"),
            Sha256::digest(public_key).into(),
            public_key,
            Zeroizing::new([7; KEY_SIZE]),
        )
    }

    #[test]
    fn envelope_round_trip() {
        let (key, identity, key_hash, public_key, shared_secret) = fixture();
        let payload = seal_key(&key, &identity, &key_hash, &public_key, &shared_secret).unwrap();
        let envelope = MacosEnvelope::parse(&payload, &identity).unwrap();
        let stored_envelope = MacosEnvelope::parse_stored(&payload).unwrap();
        let opened = envelope.open(&shared_secret).unwrap();

        assert_eq!(payload.len(), PAYLOAD_SIZE);
        assert_eq!(opened.expose_secret(), key.expose_secret());
        assert_eq!(stored_envelope.identity(), &identity);
        assert_eq!(envelope.recipient_key_hash(), &key_hash);
        assert_eq!(envelope.ephemeral_public_key(), &public_key);
    }

    #[test]
    fn wrong_identity_and_key_are_rejected() {
        let (key, identity, key_hash, public_key, shared_secret) = fixture();
        let payload = seal_key(&key, &identity, &key_hash, &public_key, &shared_secret).unwrap();

        assert!(matches!(
            MacosEnvelope::parse(&payload, &hash_identity("another-account")),
            Err(XSecError::SystemKeyInvalidated)
        ));

        let envelope = MacosEnvelope::parse(&payload, &identity).unwrap();
        assert!(matches!(
            envelope.open(&Zeroizing::new([8; KEY_SIZE])),
            Err(XSecError::AuthenticationFailed)
        ));
    }

    #[test]
    fn authenticated_fields_reject_tampering() {
        let (key, identity, key_hash, public_key, shared_secret) = fixture();
        let payload = seal_key(&key, &identity, &key_hash, &public_key, &shared_secret).unwrap();

        for offset in [
            KEY_HASH_OFFSET,
            PUBLIC_KEY_OFFSET + 1,
            SALT_OFFSET,
            NONCE_OFFSET,
            HEADER_SIZE,
            PAYLOAD_SIZE - 1,
        ] {
            let mut tampered = payload.clone();
            tampered[offset] ^= 1;
            let envelope = MacosEnvelope::parse(&tampered, &identity).unwrap();
            assert!(matches!(
                envelope.open(&shared_secret),
                Err(XSecError::AuthenticationFailed)
            ));
        }
    }

    #[test]
    fn parser_rejects_invalid_framing_version_and_platform() {
        let (key, identity, key_hash, public_key, shared_secret) = fixture();
        let payload = seal_key(&key, &identity, &key_hash, &public_key, &shared_secret).unwrap();

        assert!(matches!(
            MacosEnvelope::parse(&payload[..payload.len() - 1], &identity),
            Err(XSecError::Corrupted)
        ));

        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(matches!(
            MacosEnvelope::parse(&trailing, &identity),
            Err(XSecError::Corrupted)
        ));

        let mut wrong_version = payload;
        wrong_version[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&2u16.to_be_bytes());
        assert!(matches!(
            MacosEnvelope::parse(&wrong_version, &identity),
            Err(XSecError::UnsupportedVersion)
        ));

        for platform_magic in [WINDOWS_MAGIC, LINUX_MAGIC] {
            assert!(matches!(
                MacosEnvelope::parse(platform_magic, &identity),
                Err(XSecError::IncompatibleSystemProtector)
            ));
        }
    }

    #[test]
    fn parser_rejects_invalid_public_key_encoding() {
        let (key, identity, key_hash, public_key, shared_secret) = fixture();
        let mut payload =
            seal_key(&key, &identity, &key_hash, &public_key, &shared_secret).unwrap();
        payload[PUBLIC_KEY_OFFSET] = 2;

        assert!(matches!(
            MacosEnvelope::parse(&payload, &identity),
            Err(XSecError::Corrupted)
        ));
    }
}
