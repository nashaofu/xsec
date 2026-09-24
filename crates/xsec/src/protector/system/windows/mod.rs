mod crypto;

use self::crypto::{Challenge, SystemEnvelope, WindowsHelloPrf};
use super::hash_identity;
use crate::{XSecError, XSecProtector, XSecResult};
use secrecy::SecretBox;
use windows::{
    Security::{
        Credentials::{
            KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
        },
        Cryptography::CryptographicBuffer,
    },
    core::{Array, HSTRING},
};
use zeroize::Zeroize;

const KIND: &str = "system";
const CREDENTIAL_PREFIX: &str = "xsec-system-";
const MAX_SIGNATURE_SIZE: usize = 16 * 1024;

pub struct XSecSystemProtector {
    identity: [u8; 32],
    credential_name: String,
}

impl XSecSystemProtector {
    pub fn new(identity: impl Into<String>) -> Self {
        let identity = hash_identity(&identity.into());
        Self {
            credential_name: format!("{CREDENTIAL_PREFIX}{}", hex(&identity)),
            identity,
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
    async fn authorize(&self, challenge: &[u8]) -> XSecResult<WindowsHelloPrf> {
        let credential = self.open_credential().await?;
        Self::sign(&credential, challenge).await
    }

    async fn sign(credential: &KeyCredential, challenge: &[u8]) -> XSecResult<WindowsHelloPrf> {
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
        if length == 0 || length > MAX_SIGNATURE_SIZE {
            return Err(XSecError::AuthenticationFailed);
        }
        let mut bytes = Array::<u8>::with_len(length);
        if let Err(error) = CryptographicBuffer::CopyToByteArray(&buffer, &mut bytes) {
            bytes.zeroize();
            return Err(map_error(error));
        }
        let prf = WindowsHelloPrf::from_signature(&bytes);
        bytes.zeroize();
        Ok(prf)
    }
}

impl XSecProtector for XSecSystemProtector {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn wrap_key<'a>(&'a self, key: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        let credential = self.create_credential().await?;
        let challenge = Challenge::random()?;
        let prf = Self::sign(&credential, challenge.as_bytes()).await?;
        crypto::seal_key(key, &self.identity, &challenge, &prf)
    }

    async fn unwrap_key<'a>(&'a self, payload: &'a [u8]) -> XSecResult<SecretBox<[u8; 32]>> {
        let envelope = SystemEnvelope::parse(payload, &self.identity)?;
        let prf = self.authorize(envelope.challenge()).await?;
        envelope.open(&prf)
    }
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

    /// Manual Windows security/runtime test. It intentionally produces two
    /// Windows Hello prompts and is ignored in normal CI.
    #[tokio::test]
    #[ignore = "requires an interactive Windows Hello configuration"]
    async fn windows_hello_signature_is_stable_for_persistent_challenge() {
        let protector = XSecSystemProtector::new("xsec-manual-signature-stability-test");
        protector.delete().await.unwrap();
        let credential = protector.create_credential().await.unwrap();
        let challenge = [11u8; 16];
        let first = XSecSystemProtector::sign(&credential, &challenge)
            .await
            .unwrap();
        let second = XSecSystemProtector::sign(&credential, &challenge)
            .await
            .unwrap();
        let stable = first == second;
        protector.delete().await.unwrap();
        assert!(stable, "Windows Hello signatures were not deterministic");
    }
}
