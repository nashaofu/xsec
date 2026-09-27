use crate::{
    XSecError, XSecProtector, XSecResult, XSecStorage,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XSecStatus {
    Empty,
    Uninitialized,
    Locked,
    Unlocked,
    Destroyed,
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
    pub async fn create<P: XSecProtector>(&mut self, p: &P) -> XSecResult<()> {
        let (metadata, key) = {
            let storage = match &self.state {
                State::Uninitialized(storage) => storage,
                State::Empty => return Err(XSecError::StorageNotLoaded),
                _ => return Err(XSecError::AlreadyExists),
            };
            validate_kind(p.kind())?;
            let mut raw = Zeroizing::new([0; 32]);
            fill(raw.as_mut()).map_err(|_| XSecError::Crypto)?;
            let key = SecretBox::new(Box::new(*raw));
            let payload = p.wrap_key(&key).await?;
            let mut metadata = Metadata::new(vec![ProtectorRecord {
                kind: p.kind().into(),
                payload,
            }]);
            let bytes = metadata.encode(&key)?;
            storage.save(&bytes).await?;
            (metadata, key)
        };
        let State::Uninitialized(storage) = std::mem::replace(&mut self.state, State::Empty) else {
            unreachable!();
        };
        self.state = State::Unlocked(storage, metadata, key);
        Ok(())
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
    pub fn status(&self) -> XSecStatus {
        match self.state {
            State::Empty => XSecStatus::Empty,
            State::Uninitialized(_) => XSecStatus::Uninitialized,
            State::Locked(..) => XSecStatus::Locked,
            State::Unlocked(..) => XSecStatus::Unlocked,
            State::Destroyed(_) => XSecStatus::Destroyed,
        }
    }
    pub async fn unlock<P: XSecProtector>(&mut self, p: &P) -> XSecResult<()> {
        let key = {
            let metadata = match &self.state {
                State::Locked(_, metadata) => metadata,
                State::Empty => return Err(XSecError::StorageNotLoaded),
                State::Uninitialized(_) => return Err(XSecError::NotInitialized),
                State::Unlocked(..) => return Err(XSecError::AlreadyUnlocked),
                State::Destroyed(_) => return Err(XSecError::Destroyed),
            };
            let record = metadata
                .protectors
                .iter()
                .find(|record| record.kind == p.kind())
                .ok_or(XSecError::ProtectorNotFound)?;
            let key = p.unwrap_key(&record.payload).await?;
            metadata.verify(&key)?;
            key
        };
        let State::Locked(storage, metadata) = std::mem::replace(&mut self.state, State::Empty)
        else {
            unreachable!();
        };
        self.state = State::Unlocked(storage, metadata, key);
        Ok(())
    }

    /// Unlocks with the configured system protector using its stored identity.
    #[cfg(feature = "system-protector")]
    pub async fn unlock_system(&mut self) -> XSecResult<()> {
        let protector = match &self.state {
            State::Locked(_, metadata) => {
                let record = metadata
                    .protectors
                    .iter()
                    .find(|record| record.kind == "system")
                    .ok_or(XSecError::ProtectorNotFound)?;
                crate::XSecSystemProtector::from_payload(&record.payload)?
            }
            State::Empty => return Err(XSecError::StorageNotLoaded),
            State::Uninitialized(_) => return Err(XSecError::NotInitialized),
            State::Unlocked(..) => return Err(XSecError::AlreadyUnlocked),
            State::Destroyed(_) => return Err(XSecError::Destroyed),
        };
        self.unlock(&protector).await
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
    pub async fn add_key_protector<P: XSecProtector>(&mut self, p: &P) -> XSecResult<()> {
        let next = {
            let (storage, metadata, key) = match &self.state {
                State::Unlocked(storage, metadata, key) => (storage, metadata, key),
                _ => return Err(XSecError::Locked),
            };
            validate_kind(p.kind())?;
            if metadata
                .protectors
                .iter()
                .any(|record| record.kind == p.kind())
            {
                return Err(XSecError::ProtectorAlreadyExists);
            }
            let payload = p.wrap_key(key).await?;
            let mut next = metadata.clone();
            next.protectors.push(ProtectorRecord {
                kind: p.kind().into(),
                payload,
            });
            let bytes = next.encode(key)?;
            storage.save(&bytes).await?;
            next
        };
        let State::Unlocked(_, metadata, _) = &mut self.state else {
            unreachable!();
        };
        *metadata = next;
        Ok(())
    }
    pub async fn replace_key_protector<P: XSecProtector>(
        &mut self,
        kind: &str,
        p: &P,
    ) -> XSecResult<()> {
        let next = {
            let (storage, metadata, key) = match &self.state {
                State::Unlocked(storage, metadata, key) => (storage, metadata, key),
                _ => return Err(XSecError::Locked),
            };
            let Some(index) = metadata
                .protectors
                .iter()
                .position(|record| record.kind == kind)
            else {
                return Err(XSecError::ProtectorNotFound);
            };
            if p.kind() != kind
                && metadata
                    .protectors
                    .iter()
                    .any(|record| record.kind == p.kind())
            {
                return Err(XSecError::ProtectorAlreadyExists);
            }
            validate_kind(p.kind())?;
            let payload = p.wrap_key(key).await?;
            let mut next = metadata.clone();
            next.protectors[index] = ProtectorRecord {
                kind: p.kind().into(),
                payload,
            };
            let bytes = next.encode(key)?;
            storage.save(&bytes).await?;
            next
        };
        let State::Unlocked(_, metadata, _) = &mut self.state else {
            unreachable!();
        };
        *metadata = next;
        Ok(())
    }
    pub async fn remove_key_protector(&mut self, kind: &str) -> XSecResult<()> {
        let next = {
            let (storage, metadata, key) = match &self.state {
                State::Unlocked(storage, metadata, key) => (storage, metadata, key),
                _ => return Err(XSecError::Locked),
            };
            if !metadata.protectors.iter().any(|record| record.kind == kind) {
                return Err(XSecError::ProtectorNotFound);
            }
            if metadata.protectors.len() == 1 {
                return Err(XSecError::LastProtector);
            }
            let mut next = metadata.clone();
            next.protectors.retain(|record| record.kind != kind);
            let bytes = next.encode(key)?;
            storage.save(&bytes).await?;
            next
        };
        let State::Unlocked(_, metadata, _) = &mut self.state else {
            unreachable!();
        };
        *metadata = next;
        Ok(())
    }
    pub async fn destroy(&mut self) -> XSecResult<()> {
        match &self.state {
            State::Empty => return Err(XSecError::StorageNotLoaded),
            State::Destroyed(_) => return Ok(()),
            State::Uninitialized(storage)
            | State::Locked(storage, _)
            | State::Unlocked(storage, _, _) => storage.delete().await?,
        }
        let previous = std::mem::replace(&mut self.state, State::Empty);
        let storage = match previous {
            State::Uninitialized(storage)
            | State::Locked(storage, _)
            | State::Unlocked(storage, _, _) => storage,
            State::Empty | State::Destroyed(_) => unreachable!(),
        };
        self.state = State::Destroyed(storage);
        Ok(())
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
