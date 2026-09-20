use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{XSecError, XSecResult};

const MAGIC: &[u8; 6] = b"XSecMD";
const MAGIC_LENGTH: usize = MAGIC.len();
const VERSION: u16 = 1;
const ALGORITHM: u16 = 1;
const MAC_LENGTH: usize = 32;
pub(crate) const MAX_METADATA_LENGTH: usize = 1024 * 1024;
const MAX_PROTECTORS: usize = 16;
const MAX_KIND_LENGTH: usize = 128;
pub(crate) const MAX_PAYLOAD_LENGTH: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct ProtectorRecord {
    pub(crate) kind: String,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct Metadata {
    pub(crate) protectors: Vec<ProtectorRecord>,
    authenticated: Vec<u8>,
    mac: [u8; MAC_LENGTH],
}

impl Metadata {
    pub(crate) fn new(protectors: Vec<ProtectorRecord>) -> Self {
        Self {
            protectors,
            authenticated: Vec::new(),
            mac: [0; MAC_LENGTH],
        }
    }

    pub(crate) fn parse(blob: &[u8]) -> XSecResult<Self> {
        if blob.len() > MAX_METADATA_LENGTH
            || blob.len() < MAGIC_LENGTH + 2 + 2 + 2 + MAC_LENGTH
            || &blob[..MAGIC_LENGTH] != MAGIC
        {
            return Err(XSecError::Corrupted);
        }
        if u16::from_be_bytes([blob[MAGIC_LENGTH], blob[MAGIC_LENGTH + 1]]) != VERSION {
            return Err(XSecError::UnsupportedVersion);
        }
        let algorithm_offset = MAGIC_LENGTH + 2;
        if u16::from_be_bytes([blob[algorithm_offset], blob[algorithm_offset + 1]]) != ALGORITHM {
            return Err(XSecError::UnsupportedAlgorithm);
        }
        let count_offset = MAGIC_LENGTH + 2 + 2;
        let count = u16::from_be_bytes([blob[count_offset], blob[count_offset + 1]]) as usize;
        if count == 0 || count > MAX_PROTECTORS {
            return Err(XSecError::Corrupted);
        }
        let limit = blob.len() - MAC_LENGTH;
        let mut offset = MAGIC_LENGTH + 2 + 2 + 2;
        let mut protectors = Vec::with_capacity(count);
        for _ in 0..count {
            let kind_len = read_u16(blob, &mut offset, limit)? as usize;
            if kind_len == 0 || kind_len > MAX_KIND_LENGTH {
                return Err(XSecError::Corrupted);
            }
            let kind = std::str::from_utf8(take(blob, &mut offset, kind_len, limit)?)
                .map_err(|_| XSecError::Corrupted)?
                .to_owned();
            validate_kind(&kind)?;
            if protectors
                .last()
                .is_some_and(|last: &ProtectorRecord| last.kind >= kind)
            {
                return Err(XSecError::Corrupted);
            }
            let payload_len = read_u32(blob, &mut offset, limit)? as usize;
            if payload_len > MAX_PAYLOAD_LENGTH {
                return Err(XSecError::Corrupted);
            }
            let payload = take(blob, &mut offset, payload_len, limit)?.to_vec();
            protectors.push(ProtectorRecord { kind, payload });
        }
        if offset != limit {
            return Err(XSecError::Corrupted);
        }
        let mut mac = [0; MAC_LENGTH];
        mac.copy_from_slice(&blob[limit..]);
        Ok(Self {
            protectors,
            authenticated: blob[..limit].to_vec(),
            mac,
        })
    }

    pub(crate) fn encode(&mut self, dek: &SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        self.protectors.sort_by(|a, b| a.kind.cmp(&b.kind));
        if self.protectors.is_empty() || self.protectors.len() > MAX_PROTECTORS {
            return Err(XSecError::Corrupted);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&ALGORITHM.to_be_bytes());
        bytes.extend_from_slice(&(self.protectors.len() as u16).to_be_bytes());
        let mut previous: Option<&str> = None;
        for record in &self.protectors {
            validate_kind(&record.kind)?;
            if record.payload.len() > MAX_PAYLOAD_LENGTH
                || previous.is_some_and(|value| value >= record.kind.as_str())
            {
                return Err(XSecError::Corrupted);
            }
            previous = Some(&record.kind);
            bytes.extend_from_slice(&(record.kind.len() as u16).to_be_bytes());
            bytes.extend_from_slice(record.kind.as_bytes());
            bytes.extend_from_slice(&(record.payload.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&record.payload);
        }
        if bytes.len() + MAC_LENGTH > MAX_METADATA_LENGTH {
            return Err(XSecError::Corrupted);
        }
        self.authenticated = bytes.clone();
        self.mac = calculate_mac(dek, &bytes)?;
        bytes.extend_from_slice(&self.mac);
        Ok(bytes)
    }

    pub(crate) fn verify(&self, dek: &SecretBox<[u8; 32]>) -> XSecResult<()> {
        let key = auth_key(dek)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key[..]).map_err(|_| XSecError::Crypto)?;
        mac.update(&self.authenticated);
        mac.verify_slice(&self.mac)
            .map_err(|_| XSecError::Corrupted)
    }
}

pub(crate) fn validate_kind(kind: &str) -> XSecResult<()> {
    let bytes = kind.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_KIND_LENGTH
        || !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        || !bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
    {
        return Err(XSecError::Corrupted);
    }
    Ok(())
}

fn auth_key(dek: &SecretBox<[u8; 32]>) -> XSecResult<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, dek.expose_secret())
        .expand(b"xsec:metadata-auth:v1", key.as_mut())
        .map_err(|_| XSecError::Crypto)?;
    Ok(key)
}

fn calculate_mac(dek: &SecretBox<[u8; 32]>, data: &[u8]) -> XSecResult<[u8; 32]> {
    let key = auth_key(dek)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[..]).map_err(|_| XSecError::Crypto)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn take<'a>(blob: &'a [u8], offset: &mut usize, len: usize, limit: usize) -> XSecResult<&'a [u8]> {
    let end = offset.checked_add(len).ok_or(XSecError::Corrupted)?;
    if end > limit {
        return Err(XSecError::Corrupted);
    }
    let value = &blob[*offset..end];
    *offset = end;
    Ok(value)
}
fn read_u16(blob: &[u8], offset: &mut usize, limit: usize) -> XSecResult<u16> {
    let b = take(blob, offset, 2, limit)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
fn read_u32(blob: &[u8], offset: &mut usize, limit: usize) -> XSecResult<u32> {
    let b = take(blob, offset, 4, limit)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}
