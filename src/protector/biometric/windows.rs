use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use getrandom::fill;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use windows::{
    Security::{
        Credentials::{KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus},
        Cryptography::CryptographicBuffer,
    },
    core::{Array, HSTRING},
};

use crate::{XSecError, XSecKeyProtector, XSecResult};

const KIND: &str = "windows-hello";
const VERSION: u16 = 1;
const NONCE_LEN: usize = 12;
const CHALLENGE: &[u8] = b"xsec:windows-hello:v1:authorize";

pub struct XSecBiometricProtector {
    name: String,
}

impl XSecBiometricProtector {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    fn sign(&self) -> XSecResult<Vec<u8>> {
        let name = HSTRING::from(&self.name);
        let result = KeyCredentialManager::OpenAsync(&name)
            .map_err(map_error)?
            .get()
            .map_err(map_error)?;
        let credential = result.Credential().map_err(map_error)?;
        let input = CryptographicBuffer::CreateFromByteArray(CHALLENGE).map_err(map_error)?;
        let response = credential
            .RequestSignAsync(&input)
            .map_err(map_error)?
            .get()
            .map_err(map_error)?;
        if response.Status().map_err(map_error)? != KeyCredentialStatus::Success {
            return Err(XSecError::AuthenticationFailed);
        }
        let buffer = response.Result().map_err(map_error)?;
        let mut bytes = Array::<u8>::with_len(buffer.Length().map_err(map_error)? as usize);
        CryptographicBuffer::CopyToByteArray(&buffer, &mut bytes).map_err(map_error)?;
        Ok(bytes.as_ref().to_vec())
    }

    fn ensure_credential(&self) -> XSecResult<()> {
        let name = HSTRING::from(&self.name);
        match KeyCredentialManager::OpenAsync(&name)
            .map_err(map_error)?
            .get()
        {
            Ok(_) => Ok(()),
            Err(_) => {
                let result = KeyCredentialManager::RequestCreateAsync(
                    &name,
                    KeyCredentialCreationOption::FailIfExists,
                )
                .map_err(map_error)?
                .get()
                .map_err(map_error)?;
                if result.Status().map_err(map_error)? == KeyCredentialStatus::Success {
                    Ok(())
                } else {
                    Err(XSecError::AuthenticationFailed)
                }
            }
        }
    }

    fn derived_key(&self) -> XSecResult<[u8; 32]> {
        self.ensure_credential()?;
        let signature = self.sign()?;
        Ok(Sha256::digest(signature).into())
    }
}

impl XSecKeyProtector for XSecBiometricProtector {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn wrap_key<'a>(&'a self, key: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        let derived = self.derived_key()?;
        let mut nonce = [0u8; NONCE_LEN];
        fill(&mut nonce).map_err(|_| XSecError::Crypto)?;
        let cipher = Aes256Gcm::new_from_slice(&derived).map_err(|_| XSecError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: key.expose_secret(),
                    aad: self.name.as_bytes(),
                },
            )
            .map_err(|_| XSecError::Crypto)?;
        let name = self.name.as_bytes();
        let len = u16::try_from(name.len()).map_err(|_| XSecError::Corrupted)?;
        let mut payload = Vec::with_capacity(2 + 2 + name.len() + NONCE_LEN + ciphertext.len());
        payload.extend_from_slice(&VERSION.to_be_bytes());
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(name);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        Ok(payload)
    }

    async fn unwrap_key<'a>(&'a self, payload: &'a [u8]) -> XSecResult<SecretBox<[u8; 32]>> {
        if payload.len() < 4 + NONCE_LEN + 16
            || u16::from_be_bytes([payload[0], payload[1]]) != VERSION
        {
            return Err(XSecError::Corrupted);
        }
        let len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if payload.len() < 4 + len + NONCE_LEN + 16 || &payload[4..4 + len] != self.name.as_bytes()
        {
            return Err(XSecError::AuthenticationFailed);
        }
        let nonce_start = 4 + len;
        let nonce_end = nonce_start + NONCE_LEN;
        let derived = self.derived_key()?;
        let cipher = Aes256Gcm::new_from_slice(&derived).map_err(|_| XSecError::Crypto)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&payload[nonce_start..nonce_end]),
                Payload {
                    msg: &payload[nonce_end..],
                    aad: self.name.as_bytes(),
                },
            )
            .map_err(|_| XSecError::AuthenticationFailed)?;
        let key: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| XSecError::AuthenticationFailed)?;
        Ok(SecretBox::new(Box::new(key)))
    }
}

fn map_error<E: std::error::Error + Send + Sync + 'static>(error: E) -> XSecError {
    XSecError::Protector {
        source: Box::new(error),
    }
}
