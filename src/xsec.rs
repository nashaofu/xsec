use crate::{
    XSecError, XSecKeyProtector, XSecResult, XSecStorage,
    ciphertext::{Ciphertext, CiphertextHeader},
    metadata::{Metadata, ProtectorRecord, validate_kind},
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use getrandom::fill;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

enum State<S> {
    Empty,
    Uninitialized(S),
    Locked(S, Metadata),
    Unlocked(S, Metadata, SecretBox<[u8; 32]>),
    Destroyed(S),
}
pub struct XSec<S> {
    state: State<S>,
}

impl<S: XSecStorage> XSec<S> {
    pub fn new() -> Self {
        Self {
            state: State::Empty,
        }
    }
    pub async fn load(&mut self, storage: S) -> XSecResult<()> {
        if !matches!(self.state, State::Empty) {
            return Err(XSecError::AlreadyLoaded);
        }
        match storage.load().await? {
            Some(b) => self.state = State::Locked(storage, Metadata::parse(&b)?),
            None => self.state = State::Uninitialized(storage),
        };
        Ok(())
    }
    pub async fn create<P: XSecKeyProtector>(&mut self, p: &P) -> XSecResult<()> {
        let storage = match std::mem::replace(&mut self.state, State::Empty) {
            State::Uninitialized(s) => s,
            State::Empty => return Err(XSecError::StorageNotLoaded),
            s => {
                self.state = s;
                return Err(XSecError::AlreadyExists);
            }
        };
        let result = async {
            validate_kind(p.kind())?;
            let mut raw = Zeroizing::new([0; 32]);
            fill(raw.as_mut()).map_err(|_| XSecError::Crypto)?;
            let key = SecretBox::new(Box::new(*raw));
            let payload = p.wrap_key(&key).await?;
            let mut m = Metadata::new(vec![ProtectorRecord {
                kind: p.kind().into(),
                payload,
            }]);
            let b = m.encode(&key)?;
            storage.save(&b).await?;
            Ok((m, key))
        }
        .await;
        match result {
            Ok((m, k)) => {
                self.state = State::Unlocked(storage, m, k);
                Ok(())
            }
            Err(e) => {
                self.state = State::Uninitialized(storage);
                Err(e)
            }
        }
    }
    pub fn is_loaded(&self) -> bool {
        !matches!(self.state, State::Empty)
    }
    pub fn is_initialized(&self) -> bool {
        matches!(self.state, State::Locked(..) | State::Unlocked(..))
    }
    pub fn is_locked(&self) -> bool {
        !matches!(self.state, State::Unlocked(..))
    }
    pub fn is_destroyed(&self) -> bool {
        matches!(self.state, State::Destroyed(..))
    }
    pub async fn unlock<P: XSecKeyProtector>(&mut self, p: &P) -> XSecResult<()> {
        let (s, m) = match std::mem::replace(&mut self.state, State::Empty) {
            State::Locked(s, m) => (s, m),
            x => {
                self.state = x;
                return match &self.state {
                    State::Empty => Err(XSecError::StorageNotLoaded),
                    State::Uninitialized(_) => Err(XSecError::NotInitialized),
                    State::Unlocked(..) => Err(XSecError::AlreadyUnlocked),
                    State::Destroyed(_) => Err(XSecError::Destroyed),
                    State::Locked(..) => unreachable!(),
                };
            }
        };
        let r = async {
            let rec = m
                .protectors
                .iter()
                .find(|r| r.kind == p.kind())
                .ok_or(XSecError::ProtectorNotFound)?;
            let k = p.unwrap_key(&rec.payload).await?;
            m.verify(&k)?;
            Ok(k)
        }
        .await;
        match r {
            Ok(k) => {
                self.state = State::Unlocked(s, m, k);
                Ok(())
            }
            Err(e) => {
                self.state = State::Locked(s, m);
                Err(e)
            }
        }
    }
    pub fn lock(&mut self) -> XSecResult<()> {
        match std::mem::replace(&mut self.state, State::Empty) {
            State::Unlocked(s, m, _) => {
                self.state = State::Locked(s, m);
                Ok(())
            }
            State::Empty => {
                self.state = State::Empty;
                Err(XSecError::StorageNotLoaded)
            }
            x => {
                self.state = x;
                Ok(())
            }
        }
    }
    pub fn encrypt(&self, p: &[u8]) -> XSecResult<Vec<u8>> {
        self.encrypt_with_aad(p, &[])
    }
    pub fn decrypt(&self, c: &[u8]) -> XSecResult<Zeroizing<Vec<u8>>> {
        self.decrypt_with_aad(c, &[])
    }
    pub fn encrypt_with_aad(&self, p: &[u8], a: &[u8]) -> XSecResult<Vec<u8>> {
        let k = self.key()?;
        let h = CiphertextHeader::new()?;
        let aa = h.combined_aad(a)?;
        let c = Aes256Gcm::new_from_slice(k.expose_secret()).map_err(|_| XSecError::Crypto)?;
        let n = Nonce::try_from(h.nonce().as_slice()).map_err(|_| XSecError::Crypto)?;
        Ok(Ciphertext::new(
            h,
            c.encrypt(&n, Payload { msg: p, aad: &aa })
                .map_err(|_| XSecError::Crypto)?,
        )?
        .encode())
    }
    pub fn decrypt_with_aad(&self, b: &[u8], a: &[u8]) -> XSecResult<Zeroizing<Vec<u8>>> {
        let k = self.key()?;
        let x = Ciphertext::parse(b)?;
        let aa = x.header().combined_aad(a)?;
        let c = Aes256Gcm::new_from_slice(k.expose_secret()).map_err(|_| XSecError::Crypto)?;
        let n = Nonce::try_from(x.header().nonce().as_slice())
            .map_err(|_| XSecError::InvalidCiphertext)?;
        c.decrypt(
            &n,
            Payload {
                msg: x.encrypted_payload(),
                aad: &aa,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| XSecError::InvalidCiphertext)
    }
    pub fn key_protector_kinds(&self) -> impl Iterator<Item = &str> {
        match &self.state {
            State::Locked(_, m) | State::Unlocked(_, m, _) => m
                .protectors
                .iter()
                .map(|r| r.kind.as_str())
                .collect::<Vec<_>>()
                .into_iter(),
            _ => Vec::new().into_iter(),
        }
    }
    pub async fn add_key_protector<P: XSecKeyProtector>(&mut self, p: &P) -> XSecResult<()> {
        let (s, m, k) = match std::mem::replace(&mut self.state, State::Empty) {
            State::Unlocked(s, m, k) => (s, m, k),
            x => {
                self.state = x;
                return Err(XSecError::Locked);
            }
        };
        if m.protectors.iter().any(|r| r.kind == p.kind()) {
            self.state = State::Unlocked(s, m, k);
            return Err(XSecError::ProtectorAlreadyExists);
        }
        let payload = p.wrap_key(&k).await?;
        let mut n = m.clone();
        n.protectors.push(ProtectorRecord {
            kind: p.kind().into(),
            payload,
        });
        let b = n.encode(&k)?;
        match s.save(&b).await {
            Ok(()) => {
                self.state = State::Unlocked(s, n, k);
                Ok(())
            }
            Err(e) => {
                self.state = State::Unlocked(s, m, k);
                Err(e)
            }
        }
    }
    pub async fn remove_key_protector(&mut self, kind: &str) -> XSecResult<()> {
        let (s, m, k) = match std::mem::replace(&mut self.state, State::Empty) {
            State::Unlocked(s, m, k) => (s, m, k),
            x => {
                self.state = x;
                return Err(XSecError::Locked);
            }
        };
        if !m.protectors.iter().any(|r| r.kind == kind) {
            self.state = State::Unlocked(s, m, k);
            return Err(XSecError::ProtectorNotFound);
        }
        if m.protectors.len() == 1 {
            self.state = State::Unlocked(s, m, k);
            return Err(XSecError::LastProtector);
        }
        let mut n = m.clone();
        n.protectors.retain(|r| r.kind != kind);
        let b = n.encode(&k)?;
        match s.save(&b).await {
            Ok(()) => {
                self.state = State::Unlocked(s, n, k);
                Ok(())
            }
            Err(e) => {
                self.state = State::Unlocked(s, m, k);
                Err(e)
            }
        }
    }
    pub async fn destroy(&mut self) -> XSecResult<()> {
        let x = std::mem::replace(&mut self.state, State::Empty);
        match x {
            State::Empty => Err(XSecError::StorageNotLoaded),
            State::Destroyed(s) => {
                self.state = State::Destroyed(s);
                Ok(())
            }
            State::Uninitialized(s) | State::Locked(s, _) | State::Unlocked(s, _, _) => {
                s.delete().await?;
                self.state = State::Destroyed(s);
                Ok(())
            }
        }
    }
    pub fn into_storage(self) -> Option<S> {
        match self.state {
            State::Empty => None,
            State::Uninitialized(s)
            | State::Locked(s, _)
            | State::Unlocked(s, _, _)
            | State::Destroyed(s) => Some(s),
        }
    }
    fn key(&self) -> XSecResult<&SecretBox<[u8; 32]>> {
        match &self.state {
            State::Unlocked(_, _, k) => Ok(k),
            State::Empty => Err(XSecError::StorageNotLoaded),
            State::Uninitialized(_) => Err(XSecError::NotInitialized),
            State::Locked(..) => Err(XSecError::Locked),
            State::Destroyed(_) => Err(XSecError::Destroyed),
        }
    }
}
impl<S: XSecStorage> Default for XSec<S> {
    fn default() -> Self {
        Self::new()
    }
}
