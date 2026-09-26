use std::{collections::HashSet, ops::Range};

use base64ct::{Base64UrlUnpadded, Encoding};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    error::{CliError, CliResult, io_error},
    storage::FileXSec,
};

const ENV_VALUE_AAD: &[u8] = b"xsec-cli:env:value:v1\0";
pub(crate) const ENCRYPTED_VALUE_PREFIX: &str = "xsec:";
pub(crate) const MAX_ENV_FILE_SIZE: usize = 1024 * 1024;
pub(crate) const MAX_ENCRYPTED_ENV_FILE_SIZE: usize = MAX_ENV_FILE_SIZE * 16;
pub(crate) const MAX_PASSWORD_SIZE: usize = 4096;

pub(crate) struct EnvDocument {
    pub(crate) source: Zeroizing<Vec<u8>>,
    entries: Vec<EnvEntry>,
}

struct EnvEntry {
    name: String,
    declaration: Range<usize>,
    value: Range<usize>,
}

impl EnvDocument {
    pub(crate) fn parse(source: Zeroizing<Vec<u8>>) -> CliResult<Self> {
        let mut environment = parse_environment(&source)?;
        let entries = index_environment(&source)?;
        let matches = entries.len() == environment.len()
            && entries
                .iter()
                .zip(&environment)
                .all(|(entry, (name, _))| entry.name == *name);
        zeroize_environment(&mut environment);
        if !matches {
            return Err(CliError::InvalidEnvironment);
        }
        Ok(Self { source, entries })
    }

    pub(crate) fn set(&mut self, key: &str, value: &[u8]) -> CliResult<()> {
        let mut encoded = encode_environment_value(value)?;
        let comparison_key = normalized_environment_key(key);
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| normalized_environment_key(&entry.name) == comparison_key)
        {
            if self.source.get(entry.value.end) == Some(&b'#') {
                encoded.push(b' ');
            }
            self.source
                .splice(entry.value.clone(), encoded.iter().copied());
        } else {
            self.append(key.as_bytes(), &encoded);
        }
        if self.source.len() > MAX_ENCRYPTED_ENV_FILE_SIZE {
            return Err(CliError::UpdatedEnvironmentTooLarge);
        }
        Ok(())
    }

    pub(crate) fn stored_name(&self, key: &str) -> Option<&str> {
        let comparison_key = normalized_environment_key(key);
        self.entries
            .iter()
            .find(|entry| normalized_environment_key(&entry.name) == comparison_key)
            .map(|entry| entry.name.as_str())
    }

    pub(crate) fn unset(&mut self, key: &str) -> bool {
        let comparison_key = normalized_environment_key(key);
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| normalized_environment_key(&entry.name) == comparison_key)
        else {
            return false;
        };
        self.source.drain(entry.declaration.clone());
        true
    }

    fn append(&mut self, key: &[u8], encoded: &[u8]) {
        let newline = if self.source.windows(2).any(|value| value == b"\r\n") {
            b"\r\n".as_slice()
        } else {
            b"\n".as_slice()
        };
        let had_terminal_newline = self.source.ends_with(b"\n");
        if !self.source.is_empty() && !had_terminal_newline {
            self.source.extend_from_slice(newline);
        }
        self.source.extend_from_slice(key);
        self.source.push(b'=');
        self.source.extend_from_slice(encoded);
        if had_terminal_newline {
            self.source.extend_from_slice(newline);
        }
    }

    fn replace_values(
        &mut self,
        replacements: Vec<(Range<usize>, Zeroizing<Vec<u8>>)>,
    ) -> CliResult<()> {
        for (range, value) in replacements.into_iter().rev() {
            self.source.splice(range, value.iter().copied());
        }
        self.entries = index_environment(&self.source)?;
        Ok(())
    }
}

pub(crate) fn encrypt_environment_document(
    document: &mut EnvDocument,
    xsec: &FileXSec,
) -> CliResult<()> {
    let mut environment = parse_environment(&document.source)?;
    let mut replacements = Vec::new();
    let result = document.entries.iter().zip(&environment).try_for_each(
        |(entry, (key, value))| -> CliResult<()> {
            if value.starts_with(ENCRYPTED_VALUE_PREFIX) {
                decrypt_environment_value(key, value, xsec)?;
                return Ok(());
            }
            let encrypted = encrypt_environment_value(key, value.as_bytes(), xsec)?;
            replacements.push((entry.value.clone(), encode_environment_value(&encrypted)?));
            Ok(())
        },
    );
    zeroize_environment(&mut environment);
    result?;
    document.replace_values(replacements)?;
    if document.source.len() > MAX_ENCRYPTED_ENV_FILE_SIZE {
        return Err(CliError::UpdatedEnvironmentTooLarge);
    }
    validate_environment(&document.source)
}

pub(crate) fn decrypt_environment_document(
    document: &mut EnvDocument,
    xsec: &FileXSec,
) -> CliResult<()> {
    let mut environment = parse_environment(&document.source)?;
    let mut replacements = Vec::new();
    let result = document.entries.iter().zip(&environment).try_for_each(
        |(entry, (key, value))| -> CliResult<()> {
            if value.starts_with(ENCRYPTED_VALUE_PREFIX) {
                let plaintext = decrypt_environment_value(key, value, xsec)?;
                replacements.push((entry.value.clone(), encode_environment_value(&plaintext)?));
            }
            Ok(())
        },
    );
    zeroize_environment(&mut environment);
    result?;
    document.replace_values(replacements)?;
    if document.source.len() > MAX_ENV_FILE_SIZE {
        return Err(CliError::DecryptedEnvironmentTooLarge);
    }
    validate_environment(&document.source)
}

pub(crate) fn decrypt_environment_values(
    document: &EnvDocument,
    xsec: &FileXSec,
) -> CliResult<Vec<(String, String)>> {
    let mut environment = parse_environment(&document.source)?;
    let result = environment
        .iter_mut()
        .try_for_each(|(key, value)| -> CliResult<()> {
            let plaintext = decrypt_environment_value(key, value, xsec)?;
            let decoded = std::str::from_utf8(&plaintext)
                .map_err(|_| CliError::InvalidEncryptedVariable(key.clone()))?
                .to_owned();
            value.zeroize();
            *value = decoded;
            Ok(())
        });
    if let Err(error) = result {
        zeroize_environment(&mut environment);
        return Err(error);
    }
    Ok(environment)
}

pub(crate) fn encrypt_environment_value(
    key: &str,
    value: &[u8],
    xsec: &FileXSec,
) -> CliResult<Zeroizing<Vec<u8>>> {
    let ciphertext = xsec.encrypt_with_aad(value, &environment_value_aad(key))?;
    let encoded = Base64UrlUnpadded::encode_string(&ciphertext);
    let mut result = Zeroizing::new(Vec::with_capacity(
        ENCRYPTED_VALUE_PREFIX.len() + encoded.len(),
    ));
    result.extend_from_slice(ENCRYPTED_VALUE_PREFIX.as_bytes());
    result.extend_from_slice(encoded.as_bytes());
    Ok(result)
}

pub(crate) fn decrypt_environment_value(
    key: &str,
    value: &str,
    xsec: &FileXSec,
) -> CliResult<Zeroizing<Vec<u8>>> {
    let Some(encoded) = value.strip_prefix(ENCRYPTED_VALUE_PREFIX) else {
        return Ok(Zeroizing::new(value.as_bytes().to_vec()));
    };
    let ciphertext = Base64UrlUnpadded::decode_vec(encoded)
        .map_err(|_| CliError::InvalidEncryptedVariable(key.to_owned()))?;
    xsec.decrypt_with_aad(&ciphertext, &environment_value_aad(key))
        .map_err(|_| CliError::InvalidEncryptedVariable(key.to_owned()))
}

fn environment_value_aad(key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENV_VALUE_AAD.len() + key.len());
    aad.extend_from_slice(ENV_VALUE_AAD);
    aad.extend_from_slice(key.as_bytes());
    aad
}

pub(crate) fn load_environment_document(encrypted: Vec<u8>) -> CliResult<EnvDocument> {
    EnvDocument::parse(Zeroizing::new(encrypted))
}

fn index_environment(source: &[u8]) -> CliResult<Vec<EnvEntry>> {
    std::str::from_utf8(source).map_err(|_| CliError::InvalidEnvironment)?;
    let mut entries = Vec::new();
    let mut start = 0;
    while start < source.len() {
        let end = environment_declaration_end(source, start);
        if let Some(entry) = index_environment_declaration(source, start..end)? {
            entries.push(entry);
        }
        start = end;
    }
    Ok(entries)
}

fn environment_declaration_end(source: &[u8], start: usize) -> usize {
    let mut quote = None;
    let mut escaped = false;
    let mut comment = false;
    let mut whitespace = true;
    let mut index = start;

    while index < source.len() {
        let byte = source[index];
        if byte == b'\n' && quote.is_none() {
            return index + 1;
        }
        if comment {
            index += 1;
            continue;
        }
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if let Some(delimiter) = quote {
            match byte {
                b'\\' => escaped = true,
                value if value == delimiter => quote = None,
                _ => {}
            }
            index += 1;
            continue;
        }
        match byte {
            b'#' if whitespace => comment = true,
            b'\'' | b'"' => {
                quote = Some(byte);
                whitespace = false;
            }
            b'\\' => {
                escaped = true;
                whitespace = false;
            }
            b' ' | b'\t' | b'\r' => whitespace = true,
            _ => whitespace = false,
        }
        index += 1;
    }
    source.len()
}

fn index_environment_declaration(
    source: &[u8],
    declaration: Range<usize>,
) -> CliResult<Option<EnvEntry>> {
    let mut content_end = declaration.end;
    if content_end > declaration.start && source[content_end - 1] == b'\n' {
        content_end -= 1;
        if content_end > declaration.start && source[content_end - 1] == b'\r' {
            content_end -= 1;
        }
    }

    let mut index = skip_environment_whitespace(source, declaration.start, content_end);
    if index == content_end || source[index] == b'#' {
        return Ok(None);
    }

    let (mut name, next) = parse_environment_name(source, index, content_end)?;
    index = skip_environment_whitespace(source, next, content_end);
    if name == "export" && source.get(index) != Some(&b'=') {
        let parsed = parse_environment_name(source, index, content_end)?;
        name = parsed.0;
        index = skip_environment_whitespace(source, parsed.1, content_end);
    }
    if source.get(index) != Some(&b'=') {
        return Err(CliError::InvalidEnvironment);
    }
    index = skip_environment_whitespace(source, index + 1, content_end);
    let value_start = index;
    let value_end = environment_value_end(source, value_start, content_end);

    Ok(Some(EnvEntry {
        name,
        declaration,
        value: value_start..value_end,
    }))
}

fn parse_environment_name(source: &[u8], start: usize, end: usize) -> CliResult<(String, usize)> {
    if start == end || !(source[start].is_ascii_alphabetic() || source[start] == b'_') {
        return Err(CliError::InvalidEnvironment);
    }
    let mut index = start + 1;
    while index < end
        && (source[index].is_ascii_alphanumeric() || source[index] == b'_' || source[index] == b'.')
    {
        index += 1;
    }
    let name = std::str::from_utf8(&source[start..index])
        .map_err(|_| CliError::InvalidEnvironment)?
        .to_owned();
    Ok((name, index))
}

fn skip_environment_whitespace(source: &[u8], mut start: usize, end: usize) -> usize {
    while start < end && source[start].is_ascii_whitespace() {
        start += 1;
    }
    start
}

fn environment_value_end(source: &[u8], start: usize, end: usize) -> usize {
    if source.get(start) == Some(&b'#') {
        return start;
    }
    let mut quote = None;
    let mut escaped = false;
    let mut index = start;
    while index < end {
        let byte = source[index];
        if escaped {
            escaped = false;
        } else if let Some(delimiter) = quote {
            match byte {
                b'\\' => escaped = true,
                value if value == delimiter => quote = None,
                _ => {}
            }
        } else {
            match byte {
                b'\\' => escaped = true,
                b'\'' | b'"' => quote = Some(byte),
                b' ' | b'\t' => return index,
                _ => {}
            }
        }
        index += 1;
    }
    end
}

pub(crate) fn validate_variable_name(key: &str) -> CliResult<()> {
    let bytes = key.as_bytes();
    if bytes.is_empty()
        || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'.')
    {
        return Err(CliError::InvalidVariableName(key.to_owned()));
    }
    Ok(())
}

pub(crate) fn read_environment_value(value: Option<String>) -> CliResult<Zeroizing<Vec<u8>>> {
    let value = match value {
        Some(value) => value.into_bytes(),
        None => rpassword::prompt_password("Value: ")
            .map_err(|source| io_error("failed to read environment value", source))?
            .into_bytes(),
    };
    let value = Zeroizing::new(value);
    if value.len() > MAX_ENV_FILE_SIZE {
        return Err(CliError::EnvironmentValueTooLarge);
    }
    if value.contains(&b'\0') || value.contains(&b'\r') || std::str::from_utf8(&value).is_err() {
        return Err(CliError::InvalidEnvironmentValue);
    }
    Ok(value)
}

pub(crate) fn encode_environment_value(value: &[u8]) -> CliResult<Zeroizing<Vec<u8>>> {
    if value.contains(&b'\0') || std::str::from_utf8(value).is_err() {
        return Err(CliError::InvalidEnvironmentValue);
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(value.len() + 2));
    encoded.push(b'"');
    for byte in value {
        match byte {
            b'\\' => encoded.extend_from_slice(b"\\\\"),
            b'"' => encoded.extend_from_slice(b"\\\""),
            b'$' => encoded.extend_from_slice(b"\\$"),
            b'\n' => encoded.extend_from_slice(b"\\n"),
            value => encoded.push(*value),
        }
    }
    encoded.push(b'"');
    Ok(encoded)
}

pub(crate) fn validate_environment(bytes: &[u8]) -> CliResult<()> {
    let mut environment = parse_environment(bytes)?;
    zeroize_environment(&mut environment);
    Ok(())
}

pub(crate) fn parse_environment(bytes: &[u8]) -> CliResult<Vec<(String, String)>> {
    let mut environment = Vec::new();
    let mut names = HashSet::new();
    for entry in dotenvy::from_read_iter(bytes) {
        let (key, value) = match entry {
            Ok(entry) => entry,
            Err(_) => {
                zeroize_environment(&mut environment);
                return Err(CliError::InvalidEnvironment);
            }
        };
        if key.contains('\0') || value.contains('\0') {
            let mut value = value;
            value.zeroize();
            zeroize_environment(&mut environment);
            return Err(CliError::InvalidVariable(key));
        }
        let comparison_key = normalized_environment_key(&key);
        if !names.insert(comparison_key) {
            let mut value = value;
            value.zeroize();
            zeroize_environment(&mut environment);
            return Err(CliError::DuplicateVariable(key));
        }
        environment.push((key, value));
    }
    Ok(environment)
}

#[cfg(target_os = "windows")]
pub(crate) fn normalized_environment_key(key: &str) -> String {
    key.to_ascii_uppercase()
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn normalized_environment_key(key: &str) -> String {
    key.to_owned()
}

pub(crate) fn zeroize_environment(environment: &mut Vec<(String, String)>) {
    for (key, value) in environment {
        key.zeroize();
        value.zeroize();
    }
}
