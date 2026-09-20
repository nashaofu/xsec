use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use getrandom::fill;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::{
    XSecError, XSecKeyProtector, XSecResult, XSecStorage,
    ciphertext::{Ciphertext, CiphertextHeader},
    metadata::{Metadata, ProtectorRecord, validate_kind},
};

enum XSecState {
    Locked,
    Unlocked(SecretBox<[u8; 32]>),
    Destroyed,
}

pub struct XSec<S> {
    storage: S,
    metadata: Option<Metadata>,
    state: XSecState,
}

impl<S: XSecStorage> XSec<S> {
    pub async fn create(storage: S) -> XSecResult<Self> {
        if storage.load().await?.is_some() {
            return Err(XSecError::AlreadyExists);
        }
        Ok(Self {
            storage,
            metadata: Some(Metadata::new(Vec::new())),
            state: XSecState::Locked,
        })
    }

    pub async fn open(storage: S) -> XSecResult<Self> {
        let blob = storage.load().await?.ok_or(XSecError::NotFound)?;
        let metadata = Metadata::parse(&blob)?;
        Ok(Self {
            storage,
            metadata: Some(metadata),
            state: XSecState::Locked,
        })
    }

    pub fn is_locked(&self) -> bool {
        !matches!(self.state, XSecState::Unlocked(_))
    }
    pub fn is_destroyed(&self) -> bool {
        matches!(self.state, XSecState::Destroyed)
    }

    pub async fn unlock<P: XSecKeyProtector>(&mut self, protector: &P) -> XSecResult<()> {
        match self.state {
            XSecState::Destroyed => return Err(XSecError::Destroyed),
            XSecState::Unlocked(_) => return Err(XSecError::AlreadyUnlocked),
            XSecState::Locked => {}
        }
        let metadata = self.metadata.as_ref().ok_or(XSecError::Destroyed)?;
        let record = metadata
            .protectors
            .iter()
            .find(|record| record.kind == protector.kind())
            .ok_or(XSecError::ProtectorNotFound)?;
        let key = protector.unwrap_key(&record.payload).await?;
        metadata.verify(&key)?;
        self.state = XSecState::Unlocked(key);
        Ok(())
    }

    pub fn lock(&mut self) -> XSecResult<()> {
        match self.state {
            XSecState::Locked | XSecState::Destroyed => Ok(()),
            XSecState::Unlocked(_) => {
                self.state = XSecState::Locked;
                Ok(())
            }
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> XSecResult<Vec<u8>> {
        self.encrypt_with_aad(plaintext, &[])
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> XSecResult<Zeroizing<Vec<u8>>> {
        self.decrypt_with_aad(ciphertext, &[])
    }

    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> XSecResult<Vec<u8>> {
        let key = self.key()?;
        let header = CiphertextHeader::new()?;
        let combined_aad = header.combined_aad(aad)?;
        let cipher =
            Aes256Gcm::new_from_slice(key.expose_secret()).map_err(|_| XSecError::Crypto)?;
        let nonce_ref =
            Nonce::try_from(header.nonce().as_slice()).map_err(|_| XSecError::Crypto)?;
        let encrypted = cipher
            .encrypt(
                &nonce_ref,
                Payload {
                    msg: plaintext,
                    aad: &combined_aad,
                },
            )
            .map_err(|_| XSecError::Crypto)?;
        Ok(Ciphertext::new(header, encrypted)?.encode())
    }

    pub fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> XSecResult<Zeroizing<Vec<u8>>> {
        let key = self.key()?;
        let ciphertext = Ciphertext::parse(ciphertext)?;
        let header = ciphertext.header();
        let encrypted = ciphertext.encrypted_payload();
        let combined_aad = header.combined_aad(aad)?;
        let cipher =
            Aes256Gcm::new_from_slice(key.expose_secret()).map_err(|_| XSecError::Crypto)?;
        let nonce_ref =
            Nonce::try_from(header.nonce().as_slice()).map_err(|_| XSecError::InvalidCiphertext)?;
        let plaintext = cipher
            .decrypt(
                &nonce_ref,
                Payload {
                    msg: encrypted,
                    aad: &combined_aad,
                },
            )
            .map_err(|_| XSecError::InvalidCiphertext)?;
        Ok(Zeroizing::new(plaintext))
    }

    pub fn key_protector_kinds(&self) -> impl Iterator<Item = &str> {
        self.metadata.iter().flat_map(|metadata| {
            metadata
                .protectors
                .iter()
                .map(|record| record.kind.as_str())
        })
    }

    pub async fn add_key_protector<P: XSecKeyProtector>(
        &mut self,
        protector: &P,
    ) -> XSecResult<()> {
        validate_kind(protector.kind())?;
        let current = self.metadata.as_ref().ok_or(XSecError::Destroyed)?;
        if current
            .protectors
            .iter()
            .any(|record| record.kind == protector.kind())
        {
            return Err(XSecError::ProtectorAlreadyExists);
        }
        if current.protectors.is_empty() {
            if !matches!(self.state, XSecState::Locked) {
                return Err(XSecError::Destroyed);
            }
            let mut raw_key = Zeroizing::new([0; 32]);
            fill(raw_key.as_mut()).map_err(|_| XSecError::Crypto)?;
            let key = SecretBox::new(Box::new(*raw_key));
            let payload = protector.wrap_key(&key).await?;
            let mut next = current.clone();
            next.protectors.push(ProtectorRecord {
                kind: protector.kind().to_owned(),
                payload,
            });
            let blob = next.encode(&key)?;
            self.storage.save(&blob).await?;
            self.metadata = Some(next);
            return Ok(());
        }
        let key = self.key()?;
        let payload = protector.wrap_key(key).await?;
        let mut next = current.clone();
        next.protectors.push(ProtectorRecord {
            kind: protector.kind().to_owned(),
            payload,
        });
        let blob = next.encode(key)?;
        self.storage.save(&blob).await?;
        self.metadata = Some(next);
        Ok(())
    }

    pub async fn remove_key_protector(&mut self, kind: &str) -> XSecResult<()> {
        let _ = self.key()?;
        let current = self.metadata.as_ref().ok_or(XSecError::Destroyed)?;
        if !current.protectors.iter().any(|record| record.kind == kind) {
            return Err(XSecError::ProtectorNotFound);
        }
        if current.protectors.len() == 1 {
            return Err(XSecError::LastProtector);
        }
        let mut next = current.clone();
        next.protectors.retain(|record| record.kind != kind);
        self.commit_metadata(next).await
    }

    pub async fn replace_key_protector<P: XSecKeyProtector>(
        &mut self,
        kind: &str,
        protector: &P,
    ) -> XSecResult<()> {
        validate_kind(protector.kind())?;
        let key = self.key()?;
        let current = self.metadata.as_ref().ok_or(XSecError::Destroyed)?;
        if !current.protectors.iter().any(|record| record.kind == kind) {
            return Err(XSecError::ProtectorNotFound);
        }
        if protector.kind() != kind
            && current
                .protectors
                .iter()
                .any(|record| record.kind == protector.kind())
        {
            return Err(XSecError::ProtectorAlreadyExists);
        }
        let payload = protector.wrap_key(key).await?;
        let mut next = current.clone();
        let record = next
            .protectors
            .iter_mut()
            .find(|record| record.kind == kind)
            .ok_or(XSecError::ProtectorNotFound)?;
        record.kind = protector.kind().to_owned();
        record.payload = payload;
        self.commit_metadata(next).await
    }

    pub async fn destroy(&mut self) -> XSecResult<()> {
        if self.is_destroyed() {
            return Ok(());
        }
        self.storage.delete().await?;
        self.metadata = None;
        self.state = XSecState::Destroyed;
        Ok(())
    }

    pub fn into_storage(self) -> S {
        self.storage
    }

    fn key(&self) -> XSecResult<&SecretBox<[u8; 32]>> {
        match &self.state {
            XSecState::Unlocked(key) => Ok(key),
            XSecState::Locked => Err(XSecError::Locked),
            XSecState::Destroyed => Err(XSecError::Destroyed),
        }
    }

    async fn commit_metadata(&mut self, mut next: Metadata) -> XSecResult<()> {
        let blob = next.encode(self.key()?)?;
        self.storage.save(&blob).await?;
        self.metadata = Some(next);
        Ok(())
    }
}
