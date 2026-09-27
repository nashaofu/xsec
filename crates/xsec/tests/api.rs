use secrecy::{ExposeSecret, SecretBox};
use std::{
    future::{Future, pending, poll_fn},
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};
#[cfg(feature = "file-storage")]
use xsec::XSecFileStorage;
#[cfg(all(
    feature = "system-protector",
    not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
))]
use xsec::XSecSystemProtector;
use xsec::{
    XSec, XSecError, XSecProtector, XSecResult, XSecStatus, XSecStorage, XSecStorageError,
    XSecStorageResult,
};
#[derive(Clone, Default)]
struct Mem(Arc<Mutex<Option<Vec<u8>>>>);
impl XSecStorage for Mem {
    async fn load(&self) -> XSecStorageResult<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn save(&self, b: &[u8]) -> XSecStorageResult<()> {
        *self.0.lock().unwrap() = Some(b.to_vec());
        Ok(())
    }
    async fn delete(&self) -> XSecStorageResult<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
struct P(&'static str, u8);
impl XSecProtector for P {
    fn kind(&self) -> &'static str {
        self.0
    }
    async fn wrap_key<'a>(&'a self, k: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        Ok(k.expose_secret().iter().map(|x| x ^ self.1).collect())
    }
    async fn unwrap_key<'a>(&'a self, b: &'a [u8]) -> XSecResult<SecretBox<[u8; 32]>> {
        let v: [u8; 32] = b
            .iter()
            .map(|x| x ^ self.1)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| XSecError::AuthenticationFailed)?;
        Ok(SecretBox::new(Box::new(v)))
    }
}

struct FailingProtector;
impl XSecProtector for FailingProtector {
    fn kind(&self) -> &'static str {
        "failing"
    }

    async fn wrap_key<'a>(&'a self, _key: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        Err(XSecError::Crypto)
    }

    async fn unwrap_key<'a>(&'a self, _payload: &'a [u8]) -> XSecResult<SecretBox<[u8; 32]>> {
        Err(XSecError::Crypto)
    }
}

struct PendingProtector(&'static str);
impl XSecProtector for PendingProtector {
    fn kind(&self) -> &'static str {
        self.0
    }

    async fn wrap_key<'a>(&'a self, _key: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        pending().await
    }

    async fn unwrap_key<'a>(&'a self, _payload: &'a [u8]) -> XSecResult<SecretBox<[u8; 32]>> {
        pending().await
    }
}

#[derive(Clone, Default)]
struct FailingDeleteStorage(Mem);
impl XSecStorage for FailingDeleteStorage {
    async fn load(&self) -> XSecStorageResult<Option<Vec<u8>>> {
        self.0.load().await
    }

    async fn save(&self, bytes: &[u8]) -> XSecStorageResult<()> {
        self.0.save(bytes).await
    }

    async fn delete(&self) -> XSecStorageResult<()> {
        Err(XSecStorageError::Unavailable)
    }
}

async fn poll_pending_once<F: Future>(mut future: Pin<&mut F>) {
    poll_fn(|context| {
        assert!(future.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn lifecycle() {
    let s = Mem::default();
    let p = P("test", 7);
    let mut x = XSec::new();
    x.load(s.clone()).await.unwrap();
    assert!(!x.is_initialized());
    x.create(&p).await.unwrap();
    let c = x.encrypt_with_aad(b"hello", b"id").unwrap();
    assert_eq!(x.decrypt_with_aad(&c, b"id").unwrap().as_slice(), b"hello");
    x.lock().unwrap();
    assert!(matches!(x.decrypt(&c), Err(XSecError::Locked)));
    let mut y = XSec::new();
    y.load(s).await.unwrap();
    y.unlock(&p).await.unwrap();
    assert_eq!(y.decrypt_with_aad(&c, b"id").unwrap().as_slice(), b"hello");
}

#[tokio::test]
async fn add_key_protector_error_preserves_unlocked_state() {
    let mut xsec = XSec::new();
    xsec.load(Mem::default()).await.unwrap();
    xsec.create(&P("test", 7)).await.unwrap();

    assert!(matches!(
        xsec.add_key_protector(&FailingProtector).await,
        Err(XSecError::Crypto)
    ));
    assert_eq!(xsec.status(), XSecStatus::Unlocked);
    assert!(xsec.encrypt(b"still unlocked").is_ok());
}

#[tokio::test]
async fn cancelling_protector_operations_preserves_state() {
    let mut creating = XSec::new();
    creating.load(Mem::default()).await.unwrap();
    let pending = PendingProtector("test");
    let mut operation = Box::pin(creating.create(&pending));
    poll_pending_once(operation.as_mut()).await;
    drop(operation);
    assert_eq!(creating.status(), XSecStatus::Uninitialized);

    let storage = Mem::default();
    let protector = P("test", 7);
    let mut unlocked = XSec::new();
    unlocked.load(storage.clone()).await.unwrap();
    unlocked.create(&protector).await.unwrap();

    let pending_add = PendingProtector("pending");
    let mut add = Box::pin(unlocked.add_key_protector(&pending_add));
    poll_pending_once(add.as_mut()).await;
    drop(add);
    assert_eq!(unlocked.status(), XSecStatus::Unlocked);

    let pending_replace = PendingProtector("test");
    let mut replace = Box::pin(unlocked.replace_key_protector("test", &pending_replace));
    poll_pending_once(replace.as_mut()).await;
    drop(replace);
    assert_eq!(unlocked.status(), XSecStatus::Unlocked);

    unlocked.lock().unwrap();
    let pending_unlock = PendingProtector("test");
    let mut unlock = Box::pin(unlocked.unlock(&pending_unlock));
    poll_pending_once(unlock.as_mut()).await;
    drop(unlock);
    assert_eq!(unlocked.status(), XSecStatus::Locked);
}

#[tokio::test]
async fn destroy_error_preserves_unlocked_state() {
    let mut xsec = XSec::new();
    xsec.load(FailingDeleteStorage::default()).await.unwrap();
    xsec.create(&P("test", 7)).await.unwrap();

    assert!(matches!(
        xsec.destroy().await,
        Err(XSecError::Storage(XSecStorageError::Unavailable))
    ));
    assert_eq!(xsec.status(), XSecStatus::Unlocked);
    assert!(xsec.encrypt(b"still unlocked").is_ok());
}

#[cfg(feature = "file-storage")]
#[tokio::test]
async fn file_storage_holds_an_exclusive_lock_for_its_lifetime() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("storage");

    let mut first = XSec::new();
    first.load(XSecFileStorage::new(&path)).await.unwrap();
    first.create(&P("test", 7)).await.unwrap();

    let mut second = XSec::new();
    assert!(matches!(
        second.load(XSecFileStorage::new(&path)).await,
        Err(XSecError::Storage(XSecStorageError::Conflict))
    ));

    drop(first);
    second.load(XSecFileStorage::new(&path)).await.unwrap();
}

#[tokio::test]
async fn replaces_the_only_key_protector() {
    let storage = Mem::default();
    let old = P("password", 7);
    let new = P("password", 11);
    let mut xsec = XSec::new();
    xsec.load(storage.clone()).await.unwrap();
    xsec.create(&old).await.unwrap();
    let ciphertext = xsec.encrypt(b"secret").unwrap();

    xsec.replace_key_protector("password", &new).await.unwrap();

    let mut reloaded = XSec::new();
    reloaded.load(storage).await.unwrap();
    assert!(matches!(
        reloaded.unlock(&old).await,
        Err(XSecError::Corrupted)
    ));
    reloaded.unlock(&new).await.unwrap();
    assert_eq!(reloaded.decrypt(&ciphertext).unwrap().as_slice(), b"secret");
}

#[tokio::test]
async fn replace_key_protector_rejects_an_occupied_kind() {
    let storage = Mem::default();
    let password = P("password", 7);
    let system = P("system", 11);
    let mut xsec = XSec::new();
    xsec.load(storage).await.unwrap();
    xsec.create(&password).await.unwrap();
    xsec.add_key_protector(&system).await.unwrap();

    assert!(matches!(
        xsec.replace_key_protector("password", &P("system", 13))
            .await,
        Err(XSecError::ProtectorAlreadyExists)
    ));
    assert_eq!(xsec.status(), XSecStatus::Unlocked);
    assert_eq!(
        xsec.key_protector_kinds().collect::<Vec<_>>(),
        vec!["password", "system"]
    );
}

#[cfg(feature = "system-protector")]
#[tokio::test]
async fn unlock_system_requires_a_configured_system_protector() {
    let storage = Mem::default();
    let mut initialized = XSec::new();
    initialized.load(storage.clone()).await.unwrap();
    initialized.create(&P("test", 7)).await.unwrap();

    let mut locked = XSec::new();
    locked.load(storage).await.unwrap();

    assert!(matches!(
        locked.unlock_system().await,
        Err(XSecError::ProtectorNotFound)
    ));
}

#[test]
fn status_reports_empty() {
    let xsec: XSec<Mem> = XSec::new();
    assert_eq!(xsec.status(), XSecStatus::Empty);
}

#[cfg(all(
    feature = "system-protector",
    not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
))]
#[tokio::test]
async fn system_protector_is_explicitly_unavailable_without_a_backend() {
    let protector = XSecSystemProtector::new("stable-storage-id");
    assert_eq!(protector.kind(), "system");
    assert!(matches!(
        protector.check_availability().await,
        Err(XSecError::SystemProtectorUnavailable)
    ));
}
