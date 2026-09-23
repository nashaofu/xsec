use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use getrandom::fill;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::{XSecError, XSecResult, metadata::MAX_PAYLOAD_LENGTH, protector::XSecProtector};

const PASSWORD_KIND: &str = "password";
const PAYLOAD_VERSION: u16 = 1;
const KDF_ALGORITHM: u16 = 1;
const MEMORY_COST: u32 = 65_536;
const TIME_COST: u32 = 3;
const PARALLELISM: u32 = 1;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;
const TAG_LENGTH: usize = 16;

pub struct XSecPasswordProtector {
    password: SecretBox<Vec<u8>>,
}

impl XSecPasswordProtector {
    pub fn new(password: SecretBox<Vec<u8>>) -> Self {
        Self { password }
    }
}

impl XSecProtector for XSecPasswordProtector {
    fn kind(&self) -> &'static str {
        PASSWORD_KIND
    }

    async fn wrap_key<'a>(&'a self, key: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        let mut salt = [0; SALT_LENGTH];
        let mut nonce = [0; NONCE_LENGTH];
        fill(&mut salt).map_err(|_| XSecError::Crypto)?;
        fill(&mut nonce).map_err(|_| XSecError::Crypto)?;
        let mut header = Vec::with_capacity(63);
        header.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        header.extend_from_slice(&KDF_ALGORITHM.to_be_bytes());
        header.extend_from_slice(&MEMORY_COST.to_be_bytes());
        header.extend_from_slice(&TIME_COST.to_be_bytes());
        header.extend_from_slice(&PARALLELISM.to_be_bytes());
        header.extend_from_slice(&(KEY_LENGTH as u16).to_be_bytes());
        header.extend_from_slice(&(SALT_LENGTH as u16).to_be_bytes());
        header.extend_from_slice(&salt);
        header.push(NONCE_LENGTH as u8);
        header.extend_from_slice(&nonce);
        let kek = derive_key(
            Zeroizing::new(self.password.expose_secret().clone()),
            salt.to_vec(),
            MEMORY_COST,
            TIME_COST,
            PARALLELISM,
        )
        .await?;
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| XSecError::Crypto)?;
        let nonce_ref = Nonce::try_from(nonce.as_slice()).map_err(|_| XSecError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                &nonce_ref,
                Payload {
                    msg: key.expose_secret(),
                    aad: &header,
                },
            )
            .map_err(|_| XSecError::Crypto)?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    async fn unwrap_key<'a>(&'a self, payload: &'a [u8]) -> XSecResult<SecretBox<[u8; 32]>> {
        let parsed = PasswordPayload::parse(payload)?;
        let kek = derive_key(
            Zeroizing::new(self.password.expose_secret().clone()),
            parsed.salt.to_vec(),
            parsed.memory_cost,
            parsed.time_cost,
            parsed.parallelism,
        )
        .await?;
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| XSecError::Crypto)?;
        let nonce_ref = Nonce::try_from(parsed.nonce).map_err(|_| XSecError::Corrupted)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce_ref,
                    Payload {
                        msg: parsed.ciphertext,
                        aad: parsed.header,
                    },
                )
                .map_err(|_| XSecError::AuthenticationFailed)?,
        );
        if plaintext.len() != KEY_LENGTH {
            return Err(XSecError::Corrupted);
        }
        let mut key = [0; KEY_LENGTH];
        key.copy_from_slice(&plaintext);
        Ok(SecretBox::new(Box::new(key)))
    }
}

struct PasswordPayload<'a> {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    salt: &'a [u8],
    nonce: &'a [u8],
    header: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> PasswordPayload<'a> {
    fn parse(payload: &'a [u8]) -> XSecResult<Self> {
        if payload.len() > MAX_PAYLOAD_LENGTH
            || payload.len() < 20 + SALT_LENGTH + 1 + NONCE_LENGTH + KEY_LENGTH + TAG_LENGTH
        {
            return Err(XSecError::Corrupted);
        }
        if u16::from_be_bytes([payload[0], payload[1]]) != PAYLOAD_VERSION {
            return Err(XSecError::UnsupportedVersion);
        }
        if u16::from_be_bytes([payload[2], payload[3]]) != KDF_ALGORITHM {
            return Err(XSecError::UnsupportedAlgorithm);
        }
        let memory_cost =
            u32::from_be_bytes(payload[4..8].try_into().map_err(|_| XSecError::Corrupted)?);
        let time_cost = u32::from_be_bytes(
            payload[8..12]
                .try_into()
                .map_err(|_| XSecError::Corrupted)?,
        );
        let parallelism = u32::from_be_bytes(
            payload[12..16]
                .try_into()
                .map_err(|_| XSecError::Corrupted)?,
        );
        let derived_key_len = u16::from_be_bytes([payload[16], payload[17]]) as usize;
        if derived_key_len != KEY_LENGTH {
            return Err(XSecError::Corrupted);
        }
        let salt_len = u16::from_be_bytes([payload[18], payload[19]]) as usize;
        validate_params(memory_cost, time_cost, parallelism, salt_len)?;
        let nonce_len_index = 20usize.checked_add(salt_len).ok_or(XSecError::Corrupted)?;
        if nonce_len_index >= payload.len() || payload[nonce_len_index] as usize != NONCE_LENGTH {
            return Err(XSecError::Corrupted);
        }
        let nonce_start = nonce_len_index + 1;
        let ciphertext_start = nonce_start
            .checked_add(NONCE_LENGTH)
            .ok_or(XSecError::Corrupted)?;
        if payload.len() != ciphertext_start + KEY_LENGTH + TAG_LENGTH {
            return Err(XSecError::Corrupted);
        }
        Ok(Self {
            memory_cost,
            time_cost,
            parallelism,
            salt: &payload[20..nonce_len_index],
            nonce: &payload[nonce_start..ciphertext_start],
            header: &payload[..ciphertext_start],
            ciphertext: &payload[ciphertext_start..],
        })
    }
}

fn validate_params(memory: u32, time: u32, parallelism: u32, salt_len: usize) -> XSecResult<()> {
    if !(19_456..=262_144).contains(&memory)
        || !(2..=10).contains(&time)
        || !(1..=8).contains(&parallelism)
        || !(16..=64).contains(&salt_len)
        || memory < 8 * parallelism
    {
        return Err(XSecError::Corrupted);
    }
    Ok(())
}

async fn derive_key(
    password: Zeroizing<Vec<u8>>,
    salt: Vec<u8>,
    memory: u32,
    time: u32,
    parallelism: u32,
) -> XSecResult<Zeroizing<[u8; KEY_LENGTH]>> {
    validate_params(memory, time, parallelism, salt.len())?;
    tokio::task::spawn_blocking(move || {
        let params = Params::new(memory, time, parallelism, Some(KEY_LENGTH))
            .map_err(XSecError::protector)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0; KEY_LENGTH]);
        argon2
            .hash_password_into(&password, &salt, key.as_mut())
            .map_err(XSecError::protector)?;
        Ok(key)
    })
    .await
    .map_err(XSecError::protector)?
}
