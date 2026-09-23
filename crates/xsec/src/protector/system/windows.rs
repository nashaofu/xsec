use crate::{XSecError, XSecProtector, XSecResult};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use windows::{
    Security::{
        Credentials::{
            KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
        },
        Cryptography::CryptographicBuffer,
    },
    core::{Array, HSTRING},
};
use zeroize::Zeroizing;

const KIND: &str = "system";
const MAGIC: &[u8; 6] = b"XSecSP";
const ENVELOPE_VERSION: u16 = 1;
const KEY_SIZE: usize = 32;
const CHALLENGE_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const MAX_IDENTITY_SIZE: usize = 4096;
const CREDENTIAL_PREFIX: &str = "xsec-system-v1-";
const KDF_INFO: &[u8] = b"xsec:windows-hello:kek:v1";

pub struct XSecSystemProtector {
    identity_hash: [u8; 32],
    credential_name: String,
}

impl XSecSystemProtector {
    pub fn new(identity: impl Into<String>) -> Self {
        let identity_hash = identity_hash(&identity.into());
        Self {
            credential_name: format!("{CREDENTIAL_PREFIX}{}", hex(&identity_hash)),
            identity_hash,
        }
    }

    pub async fn check_availability(&self) -> XSecResult<()> {
        if hello_supported().await? {
            Ok(())
        } else {
            Err(XSecError::WindowsHelloNotSupported)
        }
    }

    pub async fn delete(&self) -> XSecResult<()> {
        let name = HSTRING::from(&self.credential_name);
        match KeyCredentialManager::DeleteAsync(&name)
            .map_err(map_error)?
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }

    async fn create_credential(&self) -> XSecResult<KeyCredential> {
        require_hello().await?;
        let result = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(&self.credential_name),
            KeyCredentialCreationOption::FailIfExists,
        )
        .map_err(map_error)?
        .await
        .map_err(map_error)?;
        match result.Status().map_err(map_error)? {
            KeyCredentialStatus::Success => result.Credential().map_err(map_error),
            KeyCredentialStatus::CredentialAlreadyExists => self.open_credential().await,
            status => Err(map_credential_status(status, Operation::Create)),
        }
    }

    async fn open_credential(&self) -> XSecResult<KeyCredential> {
        require_hello().await?;
        let result = KeyCredentialManager::OpenAsync(&HSTRING::from(&self.credential_name))
            .map_err(map_error)?
            .await
            .map_err(map_error)?;
        match result.Status().map_err(map_error)? {
            KeyCredentialStatus::Success => result.Credential().map_err(map_error),
            KeyCredentialStatus::NotFound => Err(XSecError::SystemKeyNotFound),
            status => Err(map_credential_status(status, Operation::Open)),
        }
    }

    /// Perform the only unlock operation used by this backend.
    ///
    /// The credential is opened and the challenge is signed for every call.
    /// There is deliberately no in-process key cache or separate yes/no
    /// authorization path: the returned signature is the input to KEK
    /// derivation, so the Windows Hello operation directly gates decryption.
    async fn authorize(&self, challenge: &[u8]) -> XSecResult<Zeroizing<Vec<u8>>> {
        let credential = self.open_credential().await?;
        Self::sign(&credential, challenge).await
    }

    async fn sign(credential: &KeyCredential, challenge: &[u8]) -> XSecResult<Zeroizing<Vec<u8>>> {
        let operation = {
            let input = CryptographicBuffer::CreateFromByteArray(challenge).map_err(map_error)?;
            credential.RequestSignAsync(&input).map_err(map_error)?
        };
        let response = operation.await.map_err(map_error)?;
        match response.Status().map_err(map_error)? {
            KeyCredentialStatus::Success => {}
            status => return Err(map_credential_status(status, Operation::Sign)),
        }
        let buffer = response.Result().map_err(map_error)?;
        let length = buffer.Length().map_err(map_error)? as usize;
        if length == 0 || length > 16 * 1024 {
            return Err(XSecError::AuthenticationFailed);
        }
        let mut bytes = Array::<u8>::with_len(length);
        CryptographicBuffer::CopyToByteArray(&buffer, &mut bytes).map_err(map_error)?;
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn derive_kek(signature: &[u8], identity_hash: &[u8; 32]) -> XSecResult<Zeroizing<[u8; 32]>> {
        let secret = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(signature)));
        let mut kek = Zeroizing::new([0u8; KEY_SIZE]);
        Hkdf::<Sha256>::new(Some(identity_hash), &secret[..])
            .expand(KDF_INFO, kek.as_mut())
            .map_err(|_| XSecError::Crypto)?;
        Ok(kek)
    }
}

impl XSecProtector for XSecSystemProtector {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn wrap_key<'a>(&'a self, key: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        let credential = self.create_credential().await?;
        let mut challenge = [0u8; CHALLENGE_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::fill(&mut challenge).map_err(|_| XSecError::Crypto)?;
        getrandom::fill(&mut nonce).map_err(|_| XSecError::Crypto)?;
        let signature = Self::sign(&credential, &challenge).await?;
        let kek = Self::derive_kek(&signature, &self.identity_hash)?;
        let mut header = Vec::with_capacity(MAGIC.len() + 2 + 32 + CHALLENGE_SIZE + NONCE_SIZE);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        header.extend_from_slice(&self.identity_hash);
        header.extend_from_slice(&challenge);
        header.extend_from_slice(&nonce);
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| XSecError::Crypto)?;
        let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| XSecError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
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
        let parsed = SystemPayload::parse(payload)?;
        if parsed.identity_hash != self.identity_hash {
            return Err(XSecError::SystemKeyInvalidated);
        }
        let signature = self.authorize(parsed.challenge).await?;
        let kek = Self::derive_kek(&signature, &self.identity_hash)?;
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| XSecError::Crypto)?;
        let nonce = Nonce::try_from(parsed.nonce).map_err(|_| XSecError::Corrupted)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: parsed.ciphertext,
                        aad: parsed.header,
                    },
                )
                .map_err(|_| XSecError::AuthenticationFailed)?,
        );
        if plaintext.len() != KEY_SIZE {
            return Err(XSecError::Corrupted);
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&plaintext);
        Ok(SecretBox::new(Box::new(key)))
    }
}

struct SystemPayload<'a> {
    identity_hash: [u8; 32],
    challenge: &'a [u8],
    nonce: &'a [u8],
    header: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> SystemPayload<'a> {
    fn parse(payload: &'a [u8]) -> XSecResult<Self> {
        const HEADER_SIZE: usize = MAGIC.len() + 2 + 32 + CHALLENGE_SIZE + NONCE_SIZE;
        const PAYLOAD_SIZE: usize = HEADER_SIZE + KEY_SIZE + TAG_SIZE;
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
        let identity_end = identity_start + 32;
        let identity_hash = payload[identity_start..identity_end]
            .try_into()
            .map_err(|_| XSecError::Corrupted)?;
        let challenge_start = identity_end;
        let challenge_end = challenge_start + CHALLENGE_SIZE;
        let nonce_start = challenge_end;
        let nonce_end = nonce_start + NONCE_SIZE;
        let ciphertext_start = nonce_end;
        Ok(Self {
            identity_hash,
            challenge: &payload[challenge_start..challenge_end],
            nonce: &payload[nonce_start..nonce_end],
            header: &payload[..ciphertext_start],
            ciphertext: &payload[ciphertext_start..],
        })
    }
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
fn identity_hash(identity: &str) -> [u8; 32] {
    assert!(
        identity.len() <= MAX_IDENTITY_SIZE,
        "XSec system protector identity exceeds 4096 UTF-8 bytes"
    );
    let mut hash = Sha256::new();
    hash.update(b"xsec:system-protector:v1");
    hash.update((identity.len() as u32).to_be_bytes());
    hash.update(identity.as_bytes());
    hash.finalize().into()
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}
async fn hello_supported() -> XSecResult<bool> {
    KeyCredentialManager::IsSupportedAsync()
        .map_err(map_error)?
        .await
        .map_err(map_error)
}
async fn require_hello() -> XSecResult<()> {
    if hello_supported().await? {
        Ok(())
    } else {
        Err(XSecError::WindowsHelloNotSupported)
    }
}
#[derive(Clone, Copy)]
enum Operation {
    Open,
    Create,
    Sign,
}
fn map_credential_status(status: KeyCredentialStatus, operation: Operation) -> XSecError {
    match status {
        KeyCredentialStatus::UserCanceled => XSecError::AuthenticationCancelled,
        KeyCredentialStatus::UserPrefersPassword => XSecError::UserVerificationRequired,
        KeyCredentialStatus::SecurityDeviceLocked => XSecError::AuthenticationFailed,
        KeyCredentialStatus::CredentialAlreadyExists => {
            if matches!(operation, Operation::Create) {
                XSecError::SystemKeyInvalidated
            } else {
                XSecError::WindowsHelloNotConfigured
            }
        }
        KeyCredentialStatus::NotFound => XSecError::SystemKeyNotFound,
        KeyCredentialStatus::UnknownError => XSecError::WindowsHelloNotConfigured,
        _ => XSecError::Crypto,
    }
}
fn map_error(error: windows::core::Error) -> XSecError {
    XSecError::Protector {
        source: Box::new(error),
    }
}
fn is_not_found(error: &windows::core::Error) -> bool {
    matches!(error.code().0 as u32, 0x80090016 | 0x80070490)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_is_not_exposed_in_credential_name() {
        let protector = XSecSystemProtector::new("account/secret-name");
        assert!(protector.credential_name.starts_with(CREDENTIAL_PREFIX));
        assert!(!protector.credential_name.contains("account"));
    }
    #[test]
    fn parser_rejects_truncated_payload() {
        assert!(matches!(
            SystemPayload::parse(&[0; 16]),
            Err(XSecError::Corrupted)
        ));
    }

    fn test_payload() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        payload.extend_from_slice(&identity_hash("test"));
        payload.extend_from_slice(&[4u8; CHALLENGE_SIZE]);
        payload.extend_from_slice(&[5u8; NONCE_SIZE]);
        payload.extend_from_slice(&[6u8; KEY_SIZE + TAG_SIZE]);
        payload
    }

    #[test]
    fn envelope_parser_accepts_v1_and_rejects_trailing_data() {
        let payload = test_payload();
        let parsed = SystemPayload::parse(&payload).unwrap();
        assert_eq!(parsed.challenge, &[4u8; CHALLENGE_SIZE]);
        let mut trailing = payload;
        trailing.push(0);
        assert!(matches!(
            SystemPayload::parse(&trailing),
            Err(XSecError::Corrupted)
        ));
    }

    #[test]
    fn envelope_parser_rejects_another_version() {
        let mut payload = test_payload();
        payload[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&2u16.to_be_bytes());
        assert!(matches!(
            SystemPayload::parse(&payload),
            Err(XSecError::UnsupportedVersion)
        ));
    }

    #[test]
    fn wrapped_key_cannot_be_opened_without_the_hello_signature() {
        let identity = identity_hash("test-account");
        let enrolled_kek = XSecSystemProtector::derive_kek(b"hello-signature", &identity).unwrap();
        let bypass_kek =
            XSecSystemProtector::derive_kek(b"attacker-controlled", &identity).unwrap();
        let nonce_bytes = [7u8; NONCE_SIZE];
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).unwrap();
        let aad = b"xsec-system-test-header";
        let ciphertext = Aes256Gcm::new_from_slice(&enrolled_kek[..])
            .unwrap()
            .encrypt(
                &nonce,
                Payload {
                    msg: &[9u8; KEY_SIZE],
                    aad,
                },
            )
            .unwrap();

        assert!(
            Aes256Gcm::new_from_slice(&bypass_kek[..])
                .unwrap()
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &ciphertext,
                        aad,
                    },
                )
                .is_err()
        );
    }

    /// Manual Windows security/runtime test. It intentionally produces two
    /// Windows Hello prompts and is ignored in normal CI.
    #[tokio::test]
    #[ignore = "requires an interactive Windows Hello configuration"]
    async fn windows_hello_signature_is_stable_for_persistent_challenge() {
        let protector = XSecSystemProtector::new("xsec-manual-signature-stability-test");
        protector.delete().await.unwrap();
        let credential = protector.create_credential().await.unwrap();
        let challenge = [11u8; CHALLENGE_SIZE];
        let first = XSecSystemProtector::sign(&credential, &challenge)
            .await
            .unwrap();
        let second = XSecSystemProtector::sign(&credential, &challenge)
            .await
            .unwrap();
        let stable = first.as_slice() == second.as_slice();
        protector.delete().await.unwrap();
        assert!(stable, "Windows Hello signatures were not deterministic");
    }
}
