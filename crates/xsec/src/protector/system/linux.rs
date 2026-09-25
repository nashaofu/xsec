use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use secrecy::{ExposeSecret, SecretBox};
use secure_types::SecureArray;
use zbus::{Connection, zvariant::{OwnedValue, Str}};
use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

use super::hash_identity;
use crate::{XSecError, XSecProtector, XSecResult};

const KIND: &str = "system";
const MAGIC: &[u8; 6] = b"XSecLP";
const WINDOWS_MAGIC: &[u8; 6] = b"XSecSP";
const PAYLOAD_VERSION: u16 = 1;
const KEY_SIZE: usize = 32;
const IDENTITY_SIZE: usize = 32;
const KEY_ID_SIZE: usize = 16;
const PAYLOAD_SIZE: usize = MAGIC.len() + 2 + IDENTITY_SIZE + KEY_ID_SIZE;
const POLKIT_ACTION: &str = "com.xsec.XSec.unlock";

struct StoredKey {
    id: [u8; KEY_ID_SIZE],
    key: SecureArray<u8, KEY_SIZE>,
}

pub struct XSecSystemProtector {
    identity: [u8; IDENTITY_SIZE],
    key: Mutex<Option<StoredKey>>,
}

impl XSecSystemProtector {
    pub fn new(identity: impl Into<String>) -> Self {
        Self {
            identity: hash_identity(&identity.into()),
            key: Mutex::new(None),
        }
    }

    pub async fn check_availability(&self) -> XSecResult<()> {
        let mut probe = [0; KEY_SIZE];
        SecureArray::from_slice_mut(&mut probe).map_err(map_secure_memory_error)?;

        let connection = Connection::system().await.map_err(map_protector_error)?;
        let proxy = AuthorityProxy::new(&connection)
            .await
            .map_err(map_protector_error)?;
        let actions = proxy
            .enumerate_actions("")
            .await
            .map_err(map_protector_error)?;
        if actions.iter().any(|action| action.action_id == POLKIT_ACTION) {
            Ok(())
        } else {
            Err(XSecError::SystemAuthenticationNotConfigured)
        }
    }

    pub async fn delete(&self) -> XSecResult<()> {
        self.key()?.take();
        Ok(())
    }

    async fn authorize(&self) -> XSecResult<()> {
        let connection = Connection::system().await.map_err(map_protector_error)?;
        let proxy = AuthorityProxy::new(&connection)
            .await
            .map_err(map_protector_error)?;
        let subject = if let Some(bus_name) = connection.unique_name() {
            let mut details = HashMap::new();
            details.insert(
                "name".to_string(),
                OwnedValue::from(Str::from(bus_name.as_str())),
            );
            Subject {
                subject_kind: "system-bus-name".to_string(),
                subject_details: details,
            }
        } else {
            Subject::new_for_owner(std::process::id(), None, None)
                .map_err(map_protector_error)?
        };
        let details = HashMap::new();
        let result = proxy
            .check_authorization(
                &subject,
                POLKIT_ACTION,
                &details,
                CheckAuthorizationFlags::AllowUserInteraction.into(),
                "",
            )
            .await
            .map_err(map_protector_error)?;

        if result.is_authorized {
            Ok(())
        } else if result
            .details
            .get("polkit.dismissed")
            .is_some_and(|value| !value.is_empty())
        {
            Err(XSecError::AuthenticationCancelled)
        } else {
            Err(XSecError::AuthenticationFailed)
        }
    }

    fn key(&self) -> XSecResult<MutexGuard<'_, Option<StoredKey>>> {
        self.key.lock().map_err(|_| XSecError::Crypto)
    }

    fn copy_key(&self, expected_id: &[u8; KEY_ID_SIZE]) -> XSecResult<SecretBox<[u8; KEY_SIZE]>> {
        let key = self.key()?;
        let stored = key.as_ref().ok_or(XSecError::SystemKeyNotFound)?;
        if stored.id != *expected_id {
            return Err(XSecError::SystemKeyInvalidated);
        }
        Ok(stored.key.unlock(|bytes| {
            let mut result = Box::new([0; KEY_SIZE]);
            result.copy_from_slice(bytes);
            SecretBox::new(result)
        }))
    }
}

impl XSecProtector for XSecSystemProtector {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn wrap_key<'a>(&'a self, key: &'a SecretBox<[u8; KEY_SIZE]>) -> XSecResult<Vec<u8>> {
        let mut key_id = [0; KEY_ID_SIZE];
        getrandom::fill(&mut key_id).map_err(|_| XSecError::Crypto)?;
        let mut bytes = *key.expose_secret();
        let secure_key =
            SecureArray::from_slice_mut(&mut bytes).map_err(map_secure_memory_error)?;
        self.key()?.replace(StoredKey {
            id: key_id,
            key: secure_key,
        });

        let mut payload = Vec::with_capacity(PAYLOAD_SIZE);
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        payload.extend_from_slice(&self.identity);
        payload.extend_from_slice(&key_id);
        Ok(payload)
    }

    async fn unwrap_key<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> XSecResult<SecretBox<[u8; KEY_SIZE]>> {
        let key_id = parse_payload(payload, &self.identity)?;
        self.authorize().await?;
        self.copy_key(key_id)
    }
}

fn parse_payload<'a>(
    payload: &'a [u8],
    expected_identity: &[u8; IDENTITY_SIZE],
) -> XSecResult<&'a [u8; KEY_ID_SIZE]> {
    if payload.get(..WINDOWS_MAGIC.len()) == Some(WINDOWS_MAGIC) {
        return Err(XSecError::IncompatibleSystemProtector);
    }
    if payload.len() != PAYLOAD_SIZE || payload.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(XSecError::Corrupted);
    }
    if u16::from_be_bytes(
        payload[MAGIC.len()..MAGIC.len() + 2]
            .try_into()
            .map_err(|_| XSecError::Corrupted)?,
    ) != PAYLOAD_VERSION
    {
        return Err(XSecError::UnsupportedVersion);
    }
    let identity_end = MAGIC.len() + 2 + IDENTITY_SIZE;
    if payload[MAGIC.len() + 2..identity_end] != expected_identity[..] {
        return Err(XSecError::SystemKeyInvalidated);
    }
    payload[identity_end..]
        .try_into()
        .map_err(|_| XSecError::Corrupted)
}

fn map_secure_memory_error(error: secure_types::Error) -> XSecError {
    XSecError::Protector {
        source: Box::new(error),
    }
}

fn map_protector_error(error: impl std::error::Error + Send + Sync + 'static) -> XSecError {
    XSecError::Protector {
        source: Box::new(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn payload_round_trip() {
        let protector = XSecSystemProtector::new("test-account");
        let key = SecretBox::new(Box::new([7; KEY_SIZE]));
        let payload = protector.wrap_key(&key).await.unwrap();

        assert_eq!(payload.len(), PAYLOAD_SIZE);
        assert!(parse_payload(&payload, &protector.identity).is_ok());
        let key_id = parse_payload(&payload, &protector.identity).unwrap();
        assert_eq!(
            protector.copy_key(key_id).unwrap().expose_secret(),
            key.expose_secret()
        );
    }

    #[tokio::test]
    async fn replacing_key_invalidates_previous_payload() {
        let protector = XSecSystemProtector::new("test-account");
        let first = protector
            .wrap_key(&SecretBox::new(Box::new([1; KEY_SIZE])))
            .await
            .unwrap();
        protector
            .wrap_key(&SecretBox::new(Box::new([2; KEY_SIZE])))
            .await
            .unwrap();

        let first_key_id = parse_payload(&first, &protector.identity).unwrap();
        assert!(matches!(
            protector.copy_key(first_key_id),
            Err(XSecError::SystemKeyInvalidated)
        ));
    }

    #[test]
    fn key_is_not_available_to_a_new_protector() {
        let protector = XSecSystemProtector::new("test-account");
        let key_id = [0; KEY_ID_SIZE];
        assert!(matches!(
            protector.copy_key(&key_id),
            Err(XSecError::SystemKeyNotFound)
        ));
    }

    #[test]
    fn parser_rejects_wrong_identity_and_platform() {
        let protector = XSecSystemProtector::new("test-account");
        let mut payload = Vec::with_capacity(PAYLOAD_SIZE);
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        payload.extend_from_slice(&protector.identity);
        payload.extend_from_slice(&[3; KEY_ID_SIZE]);

        let other_identity = hash_identity("another-account");
        assert!(matches!(
            parse_payload(&payload, &other_identity),
            Err(XSecError::SystemKeyInvalidated)
        ));

        let mut windows_payload = [0; PAYLOAD_SIZE];
        windows_payload[..WINDOWS_MAGIC.len()].copy_from_slice(WINDOWS_MAGIC);
        assert!(matches!(
            parse_payload(&windows_payload, &protector.identity),
            Err(XSecError::IncompatibleSystemProtector)
        ));
    }

    #[test]
    fn parser_rejects_invalid_framing_and_version() {
        let protector = XSecSystemProtector::new("test-account");
        let mut payload = Vec::with_capacity(PAYLOAD_SIZE);
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        payload.extend_from_slice(&protector.identity);
        payload.extend_from_slice(&[3; KEY_ID_SIZE]);

        assert!(matches!(
            parse_payload(&payload[..payload.len() - 1], &protector.identity),
            Err(XSecError::Corrupted)
        ));

        payload[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&2u16.to_be_bytes());
        assert!(matches!(
            parse_payload(&payload, &protector.identity),
            Err(XSecError::UnsupportedVersion)
        ));
    }
}
