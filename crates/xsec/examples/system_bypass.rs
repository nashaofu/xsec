//! Windows-only negative security test.
//!
//! The v4 system payload contains only a Windows Hello challenge, a public key,
//! and an AEAD-wrapped DEK. There is deliberately no independently callable
//! CNG decrypt key. This example verifies that the former NCryptDecrypt payload
//! format is no longer present.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("system_bypass is only available on Windows");
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };

    let metadata = std::fs::read("target/system.xsec")?;
    let payload = find_system_payload(&metadata)?;
    let parsed = parse_windows_payload(payload)?;
    let zero_kek = [0u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&zero_kek)?;
    let nonce = Nonce::try_from(parsed.nonce)?;
    if let Ok(plaintext) = cipher.decrypt(
        &nonce,
        Payload {
            msg: parsed.ciphertext,
            aad: parsed.aad,
        },
    ) {
        return Err(format!(
            "SECURITY FAILURE: recovered {} plaintext bytes without a Windows Hello signature",
            plaintext.len()
        )
        .into());
    }
    println!("PASS: persisted payload and a non-Hello KEK cannot recover the AEAD-wrapped DEK");
    Ok(())
}

#[cfg(target_os = "windows")]
struct ParsedWindowsPayload<'a> {
    nonce: &'a [u8],
    aad: &'a [u8],
    ciphertext: &'a [u8],
}

#[cfg(target_os = "windows")]
fn parse_windows_payload(
    payload: &[u8],
) -> Result<ParsedWindowsPayload<'_>, Box<dyn std::error::Error>> {
    if payload.get(..4) != Some(b"XSSP") || read_u16(payload, 4)? != 1 || read_u16(payload, 6)? != 1
    {
        return Err("not a Windows XSSP v1 payload".into());
    }
    let backend_len = read_u32(payload, 40)? as usize;
    if payload.len() != 44 + backend_len {
        return Err("invalid backend payload length".into());
    }
    let public_len = read_u32(payload, 50)? as usize;
    let challenge_len_offset = 54usize.checked_add(public_len).ok_or("overflow")?;
    let challenge_len = read_u16(payload, challenge_len_offset)? as usize;
    let nonce_len_offset = challenge_len_offset
        .checked_add(2 + challenge_len)
        .ok_or("overflow")?;
    let nonce_len = *payload.get(nonce_len_offset).ok_or("truncated nonce")? as usize;
    let nonce_start = nonce_len_offset + 1;
    let nonce_end = nonce_start.checked_add(nonce_len).ok_or("overflow")?;
    let ciphertext_len = read_u32(payload, nonce_end)? as usize;
    let ciphertext_start = nonce_end + 4;
    let ciphertext_end = ciphertext_start
        .checked_add(ciphertext_len)
        .ok_or("overflow")?;
    if nonce_len != 12 || ciphertext_end != payload.len() {
        return Err("invalid Windows payload".into());
    }
    Ok(ParsedWindowsPayload {
        nonce: &payload[nonce_start..nonce_end],
        aad: &payload[..ciphertext_start],
        ciphertext: &payload[ciphertext_start..ciphertext_end],
    })
}

#[cfg(target_os = "windows")]
fn read_u16(payload: &[u8], offset: usize) -> Result<u16, Box<dyn std::error::Error>> {
    Ok(u16::from_be_bytes(
        payload
            .get(offset..offset + 2)
            .ok_or("truncated u16")?
            .try_into()?,
    ))
}

#[cfg(target_os = "windows")]
fn read_u32(payload: &[u8], offset: usize) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(u32::from_be_bytes(
        payload
            .get(offset..offset + 4)
            .ok_or("truncated u32")?
            .try_into()?,
    ))
}

#[cfg(target_os = "windows")]
fn find_system_payload(blob: &[u8]) -> Result<&[u8], Box<dyn std::error::Error>> {
    const MAGIC: &[u8] = b"XSecMD";
    const MAC_SIZE: usize = 32;
    if blob.len() < MAGIC.len() + 6 + MAC_SIZE || &blob[..MAGIC.len()] != MAGIC {
        return Err("invalid XSec metadata".into());
    }
    let count = u16::from_be_bytes(blob[10..12].try_into()?) as usize;
    let limit = blob.len() - MAC_SIZE;
    let mut offset = 12usize;
    for _ in 0..count {
        let kind_len = u16::from_be_bytes(blob[offset..offset + 2].try_into()?) as usize;
        offset += 2;
        let kind = &blob[offset..offset + kind_len];
        offset += kind_len;
        let payload_len = u32::from_be_bytes(blob[offset..offset + 4].try_into()?) as usize;
        offset += 4;
        let end = offset.checked_add(payload_len).ok_or("payload overflow")?;
        if end > limit {
            return Err("truncated system payload".into());
        }
        let payload = &blob[offset..end];
        offset = end;
        if kind == b"system" {
            return Ok(payload);
        }
    }
    Err("system protector record not found".into())
}
