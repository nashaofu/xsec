mod crypto;

use std::{ffi::c_void, fmt, ptr, thread};

use core_foundation::{
    base::{CFTypeRef, TCFType, ToVoid},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFMutableDictionary,
    error::{CFError, CFErrorRef},
    number::CFNumber,
    string::CFStringRef,
};
use futures_channel::oneshot;
use objc2::{ClassType, msg_send, rc::Retained};
use objc2_foundation::NSString;
use objc2_local_authentication::{LAContext, LAPolicy};
use secrecy::{ExposeSecret, SecretBox};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    key::SecKey,
};
use security_framework_sys::{
    access_control::{kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage},
    base::{SecKeyRef, errSecAuthFailed, errSecDuplicateItem, errSecItemNotFound, errSecSuccess},
    item::{
        kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
        kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass,
        kSecClassKey, kSecMatchLimit, kSecPrivateKeyAttrs, kSecReturnRef,
        kSecUseAuthenticationContext, kSecUseDataProtectionKeychain,
    },
    key::{
        Algorithm, SecKeyCopyKeyExchangeResult, SecKeyCreateWithData, SecKeyIsAlgorithmSupported,
        kSecKeyOperationTypeKeyExchange,
    },
    keychain_item::{SecItemCopyMatching, SecItemDelete},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use self::crypto::{Identity, MacosEnvelope, PublicKey, SharedSecret};
use super::hash_identity;
use crate::{XSecError, XSecProtector, XSecResult};

const KIND: &str = "system";
const KEY_PREFIX: &str = "xsec-system-";
const AUTHENTICATION_REASON: &str = "Unlock encrypted data";
const KEY_SIZE: usize = 32;
const PUBLIC_KEY_SIZE: usize = 65;
const ERR_SEC_PARAM: i32 = -50;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;
const LA_ERROR_DOMAIN: &str = "com.apple.LocalAuthentication";
const LA_ERROR_AUTHENTICATION_FAILED: i32 = -1;
const LA_ERROR_USER_CANCEL: i32 = -2;
const LA_ERROR_USER_FALLBACK: i32 = -3;
const LA_ERROR_SYSTEM_CANCEL: i32 = -4;
const LA_ERROR_PASSCODE_NOT_SET: i32 = -5;
const LA_ERROR_BIOMETRY_NOT_AVAILABLE: i32 = -6;
const LA_ERROR_BIOMETRY_NOT_ENROLLED: i32 = -7;
const LA_ERROR_BIOMETRY_LOCKOUT: i32 = -8;
const LA_ERROR_APP_CANCEL: i32 = -9;
const LA_ERROR_NOT_INTERACTIVE: i32 = -1004;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrApplicationTag: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
}

pub struct XSecSystemProtector {
    identity: Identity,
    key_tag: Vec<u8>,
}

impl XSecSystemProtector {
    pub fn new(identity: impl Into<String>) -> Self {
        let identity = hash_identity(&identity.into());
        Self {
            key_tag: format!("{KEY_PREFIX}{}", hex(&identity)).into_bytes(),
            identity,
        }
    }

    pub async fn check_availability(&self) -> XSecResult<()> {
        let _ = self;
        run_blocking(|| {
            let context = authentication_context();
            if unsafe {
                context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            }
            .is_err()
            {
                return Err(XSecError::SystemAuthenticationNotConfigured);
            }

            let key = match create_private_key(None) {
                Ok(key) => key,
                Err(XSecError::AuthenticationFailed | XSecError::UserVerificationRequired) => {
                    return Err(XSecError::SystemAuthenticationNotConfigured);
                }
                Err(XSecError::Protector { source })
                    if source
                        .downcast_ref::<MacosError>()
                        .is_some_and(|error| error.code == ERR_SEC_PARAM) =>
                {
                    return Err(XSecError::ProviderNotSupported);
                }
                Err(error) => return Err(error),
            };
            if unsafe {
                SecKeyIsAlgorithmSupported(
                    key.as_concrete_TypeRef(),
                    kSecKeyOperationTypeKeyExchange,
                    Algorithm::ECDHKeyExchangeStandard.into(),
                ) == 0
            } {
                return Err(XSecError::ProviderNotSupported);
            }
            Ok(())
        })
        .await
    }

    pub async fn delete(&self) -> XSecResult<()> {
        let key_tag = self.key_tag.clone();
        run_blocking(move || delete_keys(&key_tag)).await
    }
}

impl XSecProtector for XSecSystemProtector {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn wrap_key<'a>(&'a self, key: &'a SecretBox<[u8; KEY_SIZE]>) -> XSecResult<Vec<u8>> {
        let identity = self.identity;
        let key_tag = self.key_tag.clone();
        let key = SecretBox::new(Box::new(*key.expose_secret()));

        run_blocking(move || {
            let recipient_private_key = open_or_create_private_key(&key_tag)?;
            let recipient_public_key = recipient_private_key
                .public_key()
                .ok_or(XSecError::Crypto)?;
            let recipient_public_bytes = export_public_key(&recipient_public_key)?;
            let recipient_key_hash: [u8; 32] = Sha256::digest(recipient_public_bytes).into();

            let ephemeral_private_key = create_software_private_key()?;
            let ephemeral_public_key = ephemeral_private_key
                .public_key()
                .ok_or(XSecError::Crypto)?;
            let ephemeral_public_bytes = export_public_key(&ephemeral_public_key)?;
            let shared_secret = raw_ecdh(&recipient_private_key, &ephemeral_public_key)?;

            crypto::seal_key(
                &key,
                &identity,
                &recipient_key_hash,
                &ephemeral_public_bytes,
                &shared_secret,
            )
        })
        .await
    }

    async fn unwrap_key<'a>(&'a self, payload: &'a [u8]) -> XSecResult<SecretBox<[u8; KEY_SIZE]>> {
        let envelope = MacosEnvelope::parse(payload, &self.identity)?;
        let key_tag = self.key_tag.clone();
        let recipient_key_hash = *envelope.recipient_key_hash();
        let ephemeral_public_key = *envelope.ephemeral_public_key();
        let payload = payload.to_vec();
        let identity = self.identity;

        run_blocking(move || {
            let private_key = open_private_key(&key_tag)?;
            let public_key = private_key.public_key().ok_or(XSecError::Crypto)?;
            let actual_key_hash: [u8; 32] = Sha256::digest(export_public_key(&public_key)?).into();
            if actual_key_hash != recipient_key_hash {
                return Err(XSecError::SystemKeyInvalidated);
            }

            let ephemeral_public_key = import_public_key(&ephemeral_public_key)?;
            let shared_secret = raw_ecdh(&private_key, &ephemeral_public_key)?;
            MacosEnvelope::parse(&payload, &identity)?.open(&shared_secret)
        })
        .await
    }
}

fn open_or_create_private_key(key_tag: &[u8]) -> XSecResult<SecKey> {
    match open_private_key(key_tag) {
        Ok(key) => Ok(key),
        Err(XSecError::SystemKeyNotFound) => match create_private_key(Some(key_tag)) {
            Ok(private_key) => {
                drop(private_key);
                open_private_key(key_tag)
            }
            Err(XSecError::Protector { source })
                if source
                    .downcast_ref::<MacosError>()
                    .is_some_and(|error| error.code == errSecDuplicateItem) =>
            {
                open_private_key(key_tag)
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

fn create_private_key(key_tag: Option<&[u8]>) -> XSecResult<SecKey> {
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
    )
    .map_err(map_security_error)?;
    let permanent = CFBoolean::from(key_tag.is_some());
    let mut private_attributes = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrIsPermanent }.to_void(),
            permanent.to_void(),
        ),
        (
            unsafe { kSecAttrAccessControl }.to_void(),
            access_control.to_void(),
        ),
    ]);
    let tag = key_tag.map(CFData::from_buffer);
    if let Some(tag) = &tag {
        private_attributes.add(&unsafe { kSecAttrApplicationTag }.to_void(), &tag.to_void());
    }

    let key_size = CFNumber::from(256);
    let attributes = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
        ),
        (
            unsafe { kSecAttrKeySizeInBits }.to_void(),
            key_size.to_void(),
        ),
        (
            unsafe { kSecAttrTokenID }.to_void(),
            unsafe { kSecAttrTokenIDSecureEnclave }.to_void(),
        ),
        (
            unsafe { kSecUseDataProtectionKeychain }.to_void(),
            CFBoolean::true_value().to_void(),
        ),
        (
            unsafe { kSecPrivateKeyAttrs }.to_void(),
            private_attributes.to_void(),
        ),
    ]);

    #[allow(deprecated)]
    SecKey::generate(attributes.to_immutable()).map_err(map_cf_error)
}

fn create_software_private_key() -> XSecResult<SecKey> {
    let key_size = CFNumber::from(256);
    let attributes = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
        ),
        (
            unsafe { kSecAttrKeySizeInBits }.to_void(),
            key_size.to_void(),
        ),
    ]);

    #[allow(deprecated)]
    SecKey::generate(attributes.to_immutable()).map_err(map_cf_error)
}

fn open_private_key(key_tag: &[u8]) -> XSecResult<SecKey> {
    let tag = CFData::from_buffer(key_tag);
    let mut query = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecClass }.to_void(),
            unsafe { kSecClassKey }.to_void(),
        ),
        (
            unsafe { kSecAttrKeyClass }.to_void(),
            unsafe { kSecAttrKeyClassPrivate }.to_void(),
        ),
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
        ),
        (unsafe { kSecAttrApplicationTag }.to_void(), tag.to_void()),
        (
            unsafe { kSecUseDataProtectionKeychain }.to_void(),
            CFBoolean::true_value().to_void(),
        ),
        (
            unsafe { kSecReturnRef }.to_void(),
            CFBoolean::true_value().to_void(),
        ),
        (
            unsafe { kSecMatchLimit }.to_void(),
            unsafe { kSecMatchLimitOne }.to_void(),
        ),
    ]);
    let context = authentication_context();
    let reason = NSString::from_str(AUTHENTICATION_REASON);
    unsafe {
        context.setLocalizedReason(&reason);
    }
    let context = Retained::as_ptr(&context).cast::<c_void>();
    query.add(&unsafe { kSecUseAuthenticationContext }.to_void(), &context);

    let mut result: CFTypeRef = ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status != errSecSuccess {
        return Err(map_status(status));
    }
    if result.is_null() {
        return Err(XSecError::SystemKeyNotFound);
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(result as SecKeyRef) })
}

fn authentication_context() -> Retained<LAContext> {
    unsafe { msg_send![LAContext::class(), new] }
}

fn delete_keys(key_tag: &[u8]) -> XSecResult<()> {
    let tag = CFData::from_buffer(key_tag);
    let query = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecClass }.to_void(),
            unsafe { kSecClassKey }.to_void(),
        ),
        (unsafe { kSecAttrApplicationTag }.to_void(), tag.to_void()),
        (
            unsafe { kSecUseDataProtectionKeychain }.to_void(),
            CFBoolean::true_value().to_void(),
        ),
    ]);
    match unsafe { SecItemDelete(query.as_concrete_TypeRef()) } {
        errSecSuccess | errSecItemNotFound => Ok(()),
        status => Err(map_status(status)),
    }
}

fn export_public_key(key: &SecKey) -> XSecResult<PublicKey> {
    let bytes = key.external_representation().ok_or(XSecError::Crypto)?;
    let bytes = bytes.bytes();
    if bytes.len() != PUBLIC_KEY_SIZE || bytes[0] != 4 {
        return Err(XSecError::Crypto);
    }
    bytes.try_into().map_err(|_| XSecError::Crypto)
}

fn import_public_key(bytes: &PublicKey) -> XSecResult<SecKey> {
    if bytes[0] != 4 {
        return Err(XSecError::Corrupted);
    }
    let data = CFData::from_buffer(bytes);
    let key_size = CFNumber::from(256);
    let attributes = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
        ),
        (
            unsafe { kSecAttrKeyClass }.to_void(),
            unsafe { kSecAttrKeyClassPublic }.to_void(),
        ),
        (
            unsafe { kSecAttrKeySizeInBits }.to_void(),
            key_size.to_void(),
        ),
    ]);
    let mut error: CFErrorRef = ptr::null_mut();
    let key = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if key.is_null() {
        return Err(take_cf_error(error));
    }
    if !error.is_null() {
        drop(unsafe { CFError::wrap_under_create_rule(error) });
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(key) })
}

fn raw_ecdh(private_key: &SecKey, public_key: &SecKey) -> XSecResult<SharedSecret> {
    let algorithm = Algorithm::ECDHKeyExchangeStandard.into();
    if unsafe {
        SecKeyIsAlgorithmSupported(
            private_key.as_concrete_TypeRef(),
            kSecKeyOperationTypeKeyExchange,
            algorithm,
        ) == 0
    } {
        return Err(XSecError::ProviderNotSupported);
    }

    let parameters = CFMutableDictionary::<*const c_void, *const c_void>::new();
    let mut error: CFErrorRef = ptr::null_mut();
    let result = unsafe {
        SecKeyCopyKeyExchangeResult(
            private_key.as_concrete_TypeRef(),
            algorithm,
            public_key.as_concrete_TypeRef(),
            parameters.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if result.is_null() {
        return Err(take_cf_error(error));
    }
    if !error.is_null() {
        drop(unsafe { CFError::wrap_under_create_rule(error) });
    }

    let data = unsafe { CFData::wrap_under_create_rule(result) };
    let bytes = Zeroizing::new(data.to_vec());
    if bytes.len() != KEY_SIZE {
        return Err(XSecError::Crypto);
    }
    let mut shared_secret = Zeroizing::new([0; KEY_SIZE]);
    shared_secret.copy_from_slice(&bytes);
    Ok(shared_secret)
}

async fn run_blocking<T, F>(operation: F) -> XSecResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> XSecResult<T> + Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    thread::Builder::new()
        .name("xsec-macos-system-protector".to_owned())
        .spawn(move || {
            let _ = sender.send(operation());
        })
        .map_err(map_protector_error)?;
    receiver.await.map_err(|_| XSecError::Crypto)?
}

fn take_cf_error(error: CFErrorRef) -> XSecError {
    if error.is_null() {
        XSecError::Crypto
    } else {
        map_cf_error(unsafe { CFError::wrap_under_create_rule(error) })
    }
}

fn map_cf_error(error: CFError) -> XSecError {
    let code = error.code() as i32;
    if error.domain().to_string() == LA_ERROR_DOMAIN {
        return match code {
            LA_ERROR_USER_CANCEL
            | LA_ERROR_USER_FALLBACK
            | LA_ERROR_SYSTEM_CANCEL
            | LA_ERROR_APP_CANCEL => XSecError::AuthenticationCancelled,
            LA_ERROR_PASSCODE_NOT_SET
            | LA_ERROR_BIOMETRY_NOT_AVAILABLE
            | LA_ERROR_BIOMETRY_NOT_ENROLLED => XSecError::SystemAuthenticationNotConfigured,
            LA_ERROR_NOT_INTERACTIVE => XSecError::UserVerificationRequired,
            LA_ERROR_AUTHENTICATION_FAILED | LA_ERROR_BIOMETRY_LOCKOUT => {
                XSecError::AuthenticationFailed
            }
            _ => map_protector_error(MacosError::new(code, error.to_string())),
        };
    }

    match code {
        ERR_SEC_USER_CANCELED => XSecError::AuthenticationCancelled,
        errSecAuthFailed => XSecError::AuthenticationFailed,
        errSecItemNotFound => XSecError::SystemKeyNotFound,
        ERR_SEC_INTERACTION_NOT_ALLOWED => XSecError::UserVerificationRequired,
        ERR_SEC_MISSING_ENTITLEMENT | ERR_SEC_NOT_AVAILABLE => {
            XSecError::SystemProtectorUnavailable
        }
        _ => map_protector_error(MacosError::new(code, error.to_string())),
    }
}

fn map_security_error(error: security_framework::base::Error) -> XSecError {
    map_status(error.code())
}

fn map_status(status: i32) -> XSecError {
    match status {
        ERR_SEC_USER_CANCELED => XSecError::AuthenticationCancelled,
        errSecAuthFailed => XSecError::AuthenticationFailed,
        errSecItemNotFound => XSecError::SystemKeyNotFound,
        ERR_SEC_INTERACTION_NOT_ALLOWED => XSecError::UserVerificationRequired,
        ERR_SEC_MISSING_ENTITLEMENT | ERR_SEC_NOT_AVAILABLE => {
            XSecError::SystemProtectorUnavailable
        }
        _ => map_protector_error(MacosError::new(
            status,
            security_framework::base::Error::from_code(status).to_string(),
        )),
    }
}

fn map_protector_error(error: impl std::error::Error + Send + Sync + 'static) -> XSecError {
    XSecError::Protector {
        source: Box::new(error),
    }
}

#[derive(Debug)]
struct MacosError {
    code: i32,
    message: String,
}

impl MacosError {
    fn new(code: i32, message: String) -> Self {
        Self { code, message }
    }
}

impl fmt::Display for MacosError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "macOS Security framework error {}: {}",
            self.code, self.message
        )
    }
}

impl std::error::Error for MacosError {}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_not_exposed_in_key_tag() {
        let protector = XSecSystemProtector::new("account/secret-name");
        let key_tag = String::from_utf8(protector.key_tag).unwrap();

        assert!(key_tag.starts_with(KEY_PREFIX));
        assert!(!key_tag.contains("account"));
    }
}
