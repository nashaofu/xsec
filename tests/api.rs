use secrecy::{ExposeSecret, SecretBox};
use std::sync::{Arc, Mutex};
use xsec::{XSec, XSecError, XSecKeyProtector, XSecResult, XSecStorage};
#[derive(Clone, Default)]
struct Mem(Arc<Mutex<Option<Vec<u8>>>>);
impl XSecStorage for Mem {
    async fn load(&self) -> XSecResult<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn save(&self, b: &[u8]) -> XSecResult<()> {
        *self.0.lock().unwrap() = Some(b.to_vec());
        Ok(())
    }
    async fn delete(&self) -> XSecResult<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
struct P(&'static str, u8);
impl XSecKeyProtector for P {
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
