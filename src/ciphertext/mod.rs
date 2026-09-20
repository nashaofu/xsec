use getrandom::fill;

use crate::{XSecError, XSecResult};

const MAGIC: &[u8; 6] = b"XSecCT";
const MAGIC_LENGTH: usize = MAGIC.len();
const VERSION: u16 = 1;
const ALGORITHM: u16 = 1;
const KEY_ID_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const HEADER_LENGTH: usize = MAGIC_LENGTH + 2 + 2 + KEY_ID_LENGTH + 1 + NONCE_LENGTH;
const AAD_DOMAIN: &[u8] = b"xsec:data-aad:v1";

pub(crate) struct CiphertextHeader {
    nonce: [u8; NONCE_LENGTH],
    raw: Vec<u8>,
}

pub(crate) struct Ciphertext {
    header: CiphertextHeader,
    encrypted_payload: Vec<u8>,
}

impl Ciphertext {
    pub(crate) fn new(header: CiphertextHeader, encrypted_payload: Vec<u8>) -> XSecResult<Self> {
        if encrypted_payload.len() < TAG_LENGTH {
            return Err(XSecError::InvalidCiphertext);
        }
        Ok(Self {
            header,
            encrypted_payload,
        })
    }

    pub(crate) fn parse(input: &[u8]) -> XSecResult<Self> {
        if input.len() < HEADER_LENGTH {
            return Err(XSecError::InvalidCiphertext);
        }
        let header = CiphertextHeader::parse(&input[..HEADER_LENGTH])?;
        Self::new(header, input[HEADER_LENGTH..].to_vec())
    }

    pub(crate) fn header(&self) -> &CiphertextHeader {
        &self.header
    }

    pub(crate) fn encrypted_payload(&self) -> &[u8] {
        &self.encrypted_payload
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.header.raw().len() + self.encrypted_payload.len());
        output.extend_from_slice(self.header.raw());
        output.extend_from_slice(&self.encrypted_payload);
        output
    }
}

impl CiphertextHeader {
    pub(crate) fn new() -> XSecResult<Self> {
        let mut nonce = [0; NONCE_LENGTH];
        fill(&mut nonce).map_err(|_| XSecError::Crypto)?;
        let mut raw = Vec::with_capacity(HEADER_LENGTH);
        raw.extend_from_slice(MAGIC);
        raw.extend_from_slice(&VERSION.to_be_bytes());
        raw.extend_from_slice(&ALGORITHM.to_be_bytes());
        raw.extend_from_slice(&[0; KEY_ID_LENGTH]);
        raw.push(NONCE_LENGTH as u8);
        raw.extend_from_slice(&nonce);
        Ok(Self { nonce, raw })
    }

    pub(crate) fn parse(input: &[u8]) -> XSecResult<Self> {
        if input.len() != HEADER_LENGTH || &input[..MAGIC_LENGTH] != MAGIC {
            return Err(XSecError::InvalidCiphertext);
        }
        if u16::from_be_bytes([input[MAGIC_LENGTH], input[MAGIC_LENGTH + 1]]) != VERSION {
            return Err(XSecError::UnsupportedVersion);
        }
        let algorithm_offset = MAGIC_LENGTH + 2;
        if u16::from_be_bytes([input[algorithm_offset], input[algorithm_offset + 1]]) != ALGORITHM {
            return Err(XSecError::UnsupportedAlgorithm);
        }
        let key_id_start = MAGIC_LENGTH + 2 + 2;
        if input[key_id_start..key_id_start + KEY_ID_LENGTH]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(XSecError::InvalidCiphertext);
        }
        let nonce_len_index = key_id_start + KEY_ID_LENGTH;
        if input[nonce_len_index] as usize != NONCE_LENGTH {
            return Err(XSecError::InvalidCiphertext);
        }
        let nonce_start = nonce_len_index + 1;
        let nonce_end = nonce_start + NONCE_LENGTH;
        let nonce: [u8; NONCE_LENGTH] = input[nonce_start..nonce_end]
            .try_into()
            .map_err(|_| XSecError::InvalidCiphertext)?;
        Ok(Self {
            nonce,
            raw: input[..nonce_end].to_vec(),
        })
    }

    pub(crate) fn nonce(&self) -> &[u8; NONCE_LENGTH] {
        &self.nonce
    }

    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub(crate) fn combined_aad(&self, user_aad: &[u8]) -> XSecResult<Vec<u8>> {
        let header_len = u32::try_from(self.raw.len()).map_err(|_| XSecError::Crypto)?;
        let aad_len = u64::try_from(user_aad.len()).map_err(|_| XSecError::Crypto)?;
        let capacity = AAD_DOMAIN
            .len()
            .checked_add(4)
            .and_then(|n| n.checked_add(self.raw.len()))
            .and_then(|n| n.checked_add(8))
            .and_then(|n| n.checked_add(user_aad.len()))
            .ok_or(XSecError::Crypto)?;
        let mut combined = Vec::with_capacity(capacity);
        combined.extend_from_slice(AAD_DOMAIN);
        combined.extend_from_slice(&header_len.to_be_bytes());
        combined.extend_from_slice(&self.raw);
        combined.extend_from_slice(&aad_len.to_be_bytes());
        combined.extend_from_slice(user_aad);
        Ok(combined)
    }
}
