use crate::{XSecError, XSecKeyProtector, XSecResult};
use secrecy::{ExposeSecret, SecretBox};
use windows::{
    Security::{
        Credentials::{KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus},
        Cryptography::CryptographicBuffer,
    },
    Win32::Security::Cryptography::{
        BCRYPT_OAEP_PADDING_INFO, CERT_KEY_SPEC, MS_PLATFORM_CRYPTO_PROVIDER,
        NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE,
        NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_PROV_HANDLE, NCRYPT_UI_POLICY, NCRYPT_UI_POLICY_PROPERTY,
        NCRYPT_UI_PROTECT_KEY_FLAG, NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt,
        NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
        NCryptSetProperty,
    },
    core::{Array, HSTRING, w},
};

const KIND: &str = "windows-cng";
const VERSION: u16 = 2;
const KEY_SIZE: usize = 32;

pub struct XSecSystemProtector {
    name: String,
}

impl XSecSystemProtector {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    fn authorize(&self) -> XSecResult<()> {
        let supported = KeyCredentialManager::IsSupportedAsync()
            .map_err(map_error)?
            .get()
            .map_err(map_error)?;
        if !supported {
            return Err(XSecError::WindowsHelloNotSupported);
        }
        let name = HSTRING::from(&self.name);
        let result = KeyCredentialManager::OpenAsync(&name)
            .map_err(map_error)?
            .get()
            .map_err(map_error)?;
        let credential = match result.Status().map_err(map_error)? {
            KeyCredentialStatus::Success => result.Credential().map_err(map_error)?,
            KeyCredentialStatus::NotFound => {
                let created = KeyCredentialManager::RequestCreateAsync(
                    &name,
                    KeyCredentialCreationOption::FailIfExists,
                )
                .map_err(map_error)?
                .get()
                .map_err(map_error)?;
                if created.Status().map_err(map_error)? != KeyCredentialStatus::Success {
                    return Err(XSecError::WindowsHelloNotConfigured);
                }
                created.Credential().map_err(map_error)?
            }
            _ => return Err(XSecError::WindowsHelloNotConfigured),
        };
        let challenge = CryptographicBuffer::CreateFromByteArray(b"xsec:windows-hello:v2")
            .map_err(map_error)?;
        let response = credential
            .RequestSignAsync(&challenge)
            .map_err(map_error)?
            .get()
            .map_err(map_error)?;
        if response.Status().map_err(map_error)? != KeyCredentialStatus::Success {
            return Err(XSecError::AuthenticationFailed);
        }
        let buffer = response.Result().map_err(map_error)?;
        let mut bytes = Array::<u8>::with_len(buffer.Length().map_err(map_error)? as usize);
        CryptographicBuffer::CopyToByteArray(&buffer, &mut bytes).map_err(map_error)?;
        if bytes.is_empty() {
            return Err(XSecError::AuthenticationFailed);
        }
        Ok(())
    }

    fn open_key(&self) -> XSecResult<(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE)> {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
            .map_err(map_error)?;
        let name = HSTRING::from(&self.name);
        let mut key = NCRYPT_KEY_HANDLE::default();
        if unsafe { NCryptOpenKey(provider, &mut key, &name, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) }
            .is_ok()
        {
            return Ok((provider, key));
        }
        unsafe {
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                w!("RSA"),
                &name,
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(map_error)?;
        let usage = NCRYPT_ALLOW_DECRYPT_FLAG.to_ne_bytes();
        let export = 0u32.to_ne_bytes();
        unsafe {
            NCryptSetProperty(
                key.into(),
                NCRYPT_KEY_USAGE_PROPERTY,
                &usage,
                NCRYPT_FLAGS(0),
            )
            .map_err(map_error)?;
            NCryptSetProperty(
                key.into(),
                NCRYPT_EXPORT_POLICY_PROPERTY,
                &export,
                NCRYPT_FLAGS(0),
            )
            .map_err(map_error)?;
        }
        let ui = NCRYPT_UI_POLICY {
            dwVersion: 1,
            dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
            pszCreationTitle: w!("XSec"),
            pszFriendlyName: w!("XSec master key"),
            pszDescription: w!("Windows Hello is required"),
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&ui as *const _) as *const u8,
                std::mem::size_of::<NCRYPT_UI_POLICY>(),
            )
        };
        unsafe {
            NCryptSetProperty(
                key.into(),
                NCRYPT_UI_POLICY_PROPERTY,
                bytes,
                NCRYPT_FLAGS(0),
            )
            .map_err(map_error)?;
            NCryptFinalizeKey(key, NCRYPT_FLAGS(0)).map_err(map_error)?;
        }
        Ok((provider, key))
    }

    fn crypt(&self, input: &[u8], decrypt: bool) -> XSecResult<Vec<u8>> {
        self.authorize()?;
        let (provider, key) = self.open_key()?;
        let padding = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: w!("SHA256"),
            pbLabel: std::ptr::null_mut(),
            cbLabel: 0,
        };
        let padding = Some((&padding as *const _) as *const _);
        let mut size = 0u32;
        unsafe {
            if decrypt {
                NCryptDecrypt(key, Some(input), padding, None, &mut size, NCRYPT_FLAGS(4))
            } else {
                NCryptEncrypt(key, Some(input), padding, None, &mut size, NCRYPT_FLAGS(4))
            }
        }
        .map_err(map_error)?;
        let mut output = vec![0u8; size as usize];
        unsafe {
            if decrypt {
                NCryptDecrypt(
                    key,
                    Some(input),
                    padding,
                    Some(&mut output),
                    &mut size,
                    NCRYPT_FLAGS(4),
                )
            } else {
                NCryptEncrypt(
                    key,
                    Some(input),
                    padding,
                    Some(&mut output),
                    &mut size,
                    NCRYPT_FLAGS(4),
                )
            }
        }
        .map_err(map_error)?;
        output.truncate(size as usize);
        unsafe {
            let _ = NCryptFreeObject(key.into());
            let _ = NCryptFreeObject(provider.into());
        }
        Ok(output)
    }
}

impl XSecKeyProtector for XSecSystemProtector {
    fn kind(&self) -> &'static str {
        KIND
    }
    async fn wrap_key<'a>(&'a self, key: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        let encrypted = self.crypt(key.expose_secret(), false)?;
        let mut payload = Vec::with_capacity(4 + encrypted.len());
        payload.extend_from_slice(&VERSION.to_be_bytes());
        payload.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        payload.extend_from_slice(&encrypted);
        Ok(payload)
    }
    async fn unwrap_key<'a>(&'a self, payload: &'a [u8]) -> XSecResult<SecretBox<[u8; 32]>> {
        if payload.len() < 5 || u16::from_be_bytes([payload[0], payload[1]]) != VERSION {
            return Err(XSecError::Corrupted);
        }
        let plaintext = self.crypt(&payload[4..], true)?;
        let key: [u8; KEY_SIZE] = plaintext
            .try_into()
            .map_err(|_| XSecError::AuthenticationFailed)?;
        Ok(SecretBox::new(Box::new(key)))
    }
}

fn map_error(error: windows::core::Error) -> XSecError {
    if error.code().0 as u32 == 0x80090029 {
        XSecError::ProviderNotSupported
    } else {
        XSecError::Protector {
            source: Box::new(error),
        }
    }
}
