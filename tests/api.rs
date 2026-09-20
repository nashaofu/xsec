use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretBox};
#[cfg(feature = "file-storage")]
use xsec::XSecFileStorage;
#[cfg(feature = "password-protector")]
use xsec::XSecPasswordProtector;
use xsec::{XSec, XSecError, XSecKeyProtector, XSecResult, XSecStorage};

#[derive(Clone, Default)]
struct MemoryStorage(Arc<Mutex<Option<Vec<u8>>>>);

impl XSecStorage for MemoryStorage {
    async fn load(&self) -> XSecResult<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn save<'a>(&'a self, data: &'a [u8]) -> XSecResult<()> {
        *self.0.lock().unwrap() = Some(data.to_vec());
        Ok(())
    }
    async fn delete(&self) -> XSecResult<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

struct TestProtector {
    kind: &'static str,
    mask: u8,
}

impl XSecKeyProtector for TestProtector {
    fn kind(&self) -> &'static str {
        self.kind
    }
    async fn wrap_key<'a>(&'a self, key: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        Ok(key
            .expose_secret()
            .iter()
            .map(|byte| byte ^ self.mask)
            .collect())
    }
    async fn unwrap_key<'a>(&'a self, payload: &'a [u8]) -> XSecResult<SecretBox<[u8; 32]>> {
        let value: Vec<_> = payload.iter().map(|byte| byte ^ self.mask).collect();
        let key: [u8; 32] = value
            .try_into()
            .map_err(|_| XSecError::AuthenticationFailed)?;
        Ok(SecretBox::new(Box::new(key)))
    }
}

#[tokio::test]
async fn lifecycle_aad_and_protector_management() {
    let storage = MemoryStorage::default();
    let first = TestProtector {
        kind: "first",
        mask: 17,
    };
    let second = TestProtector {
        kind: "second",
        mask: 29,
    };
    let mut xsec = XSec::create(storage.clone()).await.unwrap();
    assert!(xsec.is_locked());
    assert!(storage.load().await.unwrap().is_none());
    assert_eq!(xsec.key_protector_kinds().count(), 0);
    assert!(matches!(xsec.encrypt(b"x"), Err(XSecError::Locked)));
    xsec.lock().unwrap();
    xsec.add_key_protector(&first).await.unwrap();
    assert!(storage.load().await.unwrap().is_some());
    assert!(xsec.is_locked());
    xsec.unlock(&first).await.unwrap();
    let ciphertext = xsec.encrypt_with_aad(b"secret", b"record:1").unwrap();
    assert!(matches!(
        xsec.decrypt_with_aad(&ciphertext, b"record:2"),
        Err(XSecError::InvalidCiphertext)
    ));
    assert_eq!(
        xsec.decrypt_with_aad(&ciphertext, b"record:1")
            .unwrap()
            .as_slice(),
        b"secret"
    );
    xsec.add_key_protector(&second).await.unwrap();
    assert_eq!(
        xsec.key_protector_kinds().collect::<Vec<_>>(),
        ["first", "second"]
    );
    xsec.remove_key_protector("first").await.unwrap();
    assert!(matches!(
        xsec.remove_key_protector("second").await,
        Err(XSecError::LastProtector)
    ));
    xsec.lock().unwrap();
    assert!(matches!(xsec.encrypt(b"x"), Err(XSecError::Locked)));
    drop(xsec);
    let mut reopened = XSec::open(storage).await.unwrap();
    reopened.unlock(&second).await.unwrap();
    assert_eq!(
        reopened
            .decrypt_with_aad(&ciphertext, b"record:1")
            .unwrap()
            .as_slice(),
        b"secret"
    );
    reopened.destroy().await.unwrap();
    assert!(reopened.is_locked() && reopened.is_destroyed());
    assert_eq!(reopened.key_protector_kinds().count(), 0);
    assert!(matches!(
        reopened.decrypt(&ciphertext),
        Err(XSecError::Destroyed)
    ));
    reopened.destroy().await.unwrap();
}

#[tokio::test]
async fn metadata_tampering_is_detected_after_unlock() {
    let storage = MemoryStorage::default();
    let protector = TestProtector {
        kind: "test",
        mask: 42,
    };
    let mut xsec = XSec::create(storage.clone()).await.unwrap();
    xsec.add_key_protector(&protector).await.unwrap();
    drop(xsec);
    let mut blob = storage.load().await.unwrap().unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 1;
    storage.save(&blob).await.unwrap();
    let mut reopened = XSec::open(storage).await.unwrap();
    assert!(matches!(
        reopened.unlock(&protector).await,
        Err(XSecError::Corrupted)
    ));
    assert!(reopened.is_locked());
}

#[tokio::test]
async fn ciphertext_header_tampering_is_detected() {
    let mut xsec = XSec::create(MemoryStorage::default()).await.unwrap();
    let protector = TestProtector {
        kind: "test",
        mask: 7,
    };
    xsec.add_key_protector(&protector).await.unwrap();
    xsec.unlock(&protector).await.unwrap();
    let mut ciphertext = xsec.encrypt(b"secret").unwrap();
    ciphertext[20] ^= 1;
    assert!(matches!(
        xsec.decrypt(&ciphertext),
        Err(XSecError::InvalidCiphertext)
    ));
}

#[tokio::test]
#[cfg(feature = "password-protector")]
async fn password_protector_rejects_wrong_password() {
    let storage = MemoryStorage::default();
    let correct =
        XSecPasswordProtector::new(SecretBox::new(Box::new(b"correct password".to_vec())));
    let mut xsec = XSec::create(storage.clone()).await.unwrap();
    xsec.add_key_protector(&correct).await.unwrap();
    drop(xsec);
    let wrong = XSecPasswordProtector::new(SecretBox::new(Box::new(b"wrong password".to_vec())));
    let mut reopened = XSec::open(storage.clone()).await.unwrap();
    assert!(matches!(
        reopened.unlock(&wrong).await,
        Err(XSecError::AuthenticationFailed)
    ));
    assert!(reopened.is_locked());
    let mut reopened = XSec::open(storage).await.unwrap();
    reopened.unlock(&correct).await.unwrap();
    assert!(!reopened.is_locked());
}

#[tokio::test]
#[cfg(feature = "file-storage")]
async fn file_storage_exists_tracks_file_lifecycle() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.xsec");
    let storage = XSecFileStorage::new(&path);

    assert!(!storage.exists().await.unwrap());
    storage.save(b"metadata").await.unwrap();
    assert!(storage.exists().await.unwrap());
    storage.delete().await.unwrap();
    assert!(!storage.exists().await.unwrap());
}

#[tokio::test]
#[cfg(feature = "file-storage")]
async fn file_storage_atomically_replaces_existing_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.xsec");
    let first = TestProtector {
        kind: "first",
        mask: 1,
    };
    let second = TestProtector {
        kind: "second",
        mask: 2,
    };
    let mut xsec = XSec::create(XSecFileStorage::new(&path)).await.unwrap();
    xsec.add_key_protector(&first).await.unwrap();
    xsec.unlock(&first).await.unwrap();
    xsec.add_key_protector(&second).await.unwrap();
    drop(xsec);
    let mut reopened = XSec::open(XSecFileStorage::new(&path)).await.unwrap();
    reopened.unlock(&second).await.unwrap();
    assert_eq!(
        reopened.key_protector_kinds().collect::<Vec<_>>(),
        ["first", "second"]
    );
}
