use std::{ffi::OsString, path::PathBuf};

use clap::Parser;
use secrecy::SecretBox;
use xsec::{XSec, XSecFileStorage, XSecPasswordProtector};
use zeroize::Zeroizing;

use crate::{
    cli::{
        AddSystemProtectorArgs, Cli, Command, DelArgs, InitArgs, InspectArgs, ProtectorAddCommand,
        ProtectorArgs, ProtectorCommand, ProtectorKind, RemoveProtectorArgs, RunArgs, SetArgs,
    },
    environment::{
        ENCRYPTED_VALUE_PREFIX, EnvDocument, decrypt_environment_document,
        decrypt_environment_value, decrypt_environment_values, encode_environment_value,
        encrypt_environment_document, encrypt_environment_value, load_environment_document,
        parse_environment, validate_environment,
    },
    error::CliError,
    file::atomic_replace_if_unchanged,
    storage::{FileXSec, strip_line_ending},
};

async fn create_test_xsec() -> (tempfile::TempDir, FileXSec) {
    let directory = tempfile::tempdir().unwrap();
    let protector = XSecPasswordProtector::new(SecretBox::new(Box::new(b"password".to_vec())));
    let mut xsec = XSec::new();
    xsec.load(XSecFileStorage::new(directory.path().join("storage")))
        .await
        .unwrap();
    xsec.create(&protector).await.unwrap();
    (directory, xsec)
}

#[test]
fn parses_run_command_after_separator() {
    let cli = Cli::try_parse_from(["xsec", "run", "-f", ".xsec.test", "--", "printenv"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Run(RunArgs { file, command, .. })
            if file == PathBuf::from(".xsec.test")
                && command == vec![OsString::from("printenv")]
    ));
}

#[test]
fn uses_storage_as_the_key_storage_option() {
    let cli = Cli::try_parse_from(["xsec", "inspect", "--storage", ".xsec.storage"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Inspect(InspectArgs { storage })
            if storage == PathBuf::from(".xsec.storage")
    ));
    assert!(Cli::try_parse_from(["xsec", "inspect", "--metadata", ".xsec.keys"]).is_err());
}

#[test]
fn uses_password_as_the_standard_input_flag() {
    let cli = Cli::try_parse_from(["xsec", "init", "--password"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Init(InitArgs { password: true, .. })
    ));
    assert!(Cli::try_parse_from(["xsec", "init", "--password-stdin"]).is_err());
    assert!(Cli::try_parse_from(["xsec", "init", "--password", "secret"]).is_err());
}

#[test]
fn initialization_is_always_password_protected() {
    assert!(Cli::try_parse_from(["xsec", "init"]).is_ok());
    assert!(Cli::try_parse_from(["xsec", "init", "--protector", "system"]).is_err());
    assert!(Cli::try_parse_from(["xsec", "init", "--identity", "project-id"]).is_err());
}

#[test]
fn parses_add_system_protector() {
    let cli = Cli::try_parse_from([
        "xsec",
        "protector",
        "add",
        "system",
        "--identity",
        "project-id",
        "--storage",
        ".xsec.custom.keys",
        "--password",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Protector(ProtectorArgs {
            command: ProtectorCommand::Add(ProtectorAddArgs {
                protector: ProtectorAddCommand::System(AddSystemProtectorArgs {
                    identity,
                    storage,
                    password: true,
                }),
            }),
        }) if identity == "project-id" && storage == PathBuf::from(".xsec.custom.keys")
    ));
    assert!(Cli::try_parse_from(["xsec", "get", "TOKEN", "--identity", "project-id"]).is_err());
}

#[test]
fn parses_remove_protector() {
    let cli = Cli::try_parse_from([
        "xsec",
        "protector",
        "remove",
        "system",
        "--storage",
        ".xsec.custom.keys",
        "--unlock-with",
        "password",
        "--password",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Protector(ProtectorArgs {
            command: ProtectorCommand::Remove(RemoveProtectorArgs {
                kind: ProtectorKind::System,
                storage,
                unlock_with: Some(ProtectorKind::Password),
                password: true,
            }),
        }) if storage == PathBuf::from(".xsec.custom.keys")
    ));
}

#[test]
fn rejects_stdout_with_output_file() {
    assert!(Cli::try_parse_from(["xsec", "decrypt", "--stdout", "--output", ".env"]).is_err());
}

#[test]
fn parses_top_level_set_for_interactive_input() {
    let cli = Cli::try_parse_from(["xsec", "set", "TOKEN", "-f", ".xsec.test"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Set(SetArgs {
            key,
            value: None,
            file,
            ..
        }) if key == "TOKEN" && file == PathBuf::from(".xsec.test")
    ));
}

#[test]
fn parses_set_value_as_a_positional_argument() {
    let cli = Cli::try_parse_from(["xsec", "set", "TOKEN", "secret"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Set(SetArgs {
            key,
            value: Some(value),
            ..
        }) if key == "TOKEN" && value == "secret"
    ));
    assert!(Cli::try_parse_from(["xsec", "set", "TOKEN", "first", "second"]).is_err());
    assert!(Cli::try_parse_from(["xsec", "set", "TOKEN", "--stdin"]).is_err());
}

#[test]
fn parses_top_level_del() {
    let cli = Cli::try_parse_from(["xsec", "del", "TOKEN", "-f", ".xsec.test"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Del(DelArgs { key, file, .. })
            if key == "TOKEN" && file == PathBuf::from(".xsec.test")
    ));
}

#[test]
fn set_preserves_document_formatting_and_other_values() {
    let source = Zeroizing::new(
            b"# heading\r\nexport FIRST = 'old' # keep\r\nMULTI=\"line1\r\nline2\"\r\nEMPTY=   # empty\r\n"
                .to_vec(),
        );
    let mut document = EnvDocument::parse(source).unwrap();

    document.set("FIRST", b"new $\"\n\\").unwrap();

    assert_eq!(
            document.source.as_slice(),
            b"# heading\r\nexport FIRST = \"new \\$\\\"\\n\\\\\" # keep\r\nMULTI=\"line1\r\nline2\"\r\nEMPTY=   # empty\r\n"
        );
    validate_environment(&document.source).unwrap();
}

#[test]
fn set_preserves_an_inline_comment_after_an_empty_value() {
    let mut document = EnvDocument::parse(Zeroizing::new(b"EMPTY=   # keep\n".to_vec())).unwrap();

    document.set("EMPTY", b"value").unwrap();

    assert_eq!(document.source.as_slice(), b"EMPTY=   \"value\" # keep\n");
}

#[test]
fn set_appends_with_the_existing_newline_style() {
    let mut document = EnvDocument::parse(Zeroizing::new(b"FIRST=one\r\n".to_vec())).unwrap();

    document.set("SECOND", b"two").unwrap();

    assert_eq!(
        document.source.as_slice(),
        b"FIRST=one\r\nSECOND=\"two\"\r\n"
    );
}

#[test]
fn unset_removes_only_the_exact_multiline_declaration() {
    let source = Zeroizing::new(b"KEY=\"first\nsecond\"\nKEY_SUFFIX=keep\n# trailing\n".to_vec());
    let mut document = EnvDocument::parse(source).unwrap();

    assert!(document.unset("KEY"));

    assert_eq!(document.source.as_slice(), b"KEY_SUFFIX=keep\n# trailing\n");
}

#[test]
fn unset_reports_a_missing_exact_key_without_changes() {
    let source = b"KEY_SUFFIX=keep\n".to_vec();
    let mut document = EnvDocument::parse(Zeroizing::new(source.clone())).unwrap();

    assert!(!document.unset("KEY"));

    assert_eq!(document.source.as_slice(), source);
}

#[test]
fn environment_value_encoding_round_trips() {
    let encoded = encode_environment_value(b"slash\\ quote\" dollar$ line\n").unwrap();
    let mut document = b"VALUE=".to_vec();
    document.extend_from_slice(&encoded);
    document.push(b'\n');

    assert_eq!(
        parse_environment(&document).unwrap(),
        vec![(
            "VALUE".to_owned(),
            "slash\\ quote\" dollar$ line\n".to_owned()
        )]
    );
}

#[tokio::test]
async fn encrypts_and_decrypts_each_environment_value() {
    let (_directory, xsec) = create_test_xsec().await;
    let source = Zeroizing::new(b"# heading\nFIRST=one # keep\nSECOND=one\n".to_vec());
    let mut document = EnvDocument::parse(source).unwrap();

    encrypt_environment_document(&mut document, &xsec).unwrap();

    let encrypted = parse_environment(&document.source).unwrap();
    assert!(
        encrypted
            .iter()
            .all(|(_, value)| value.starts_with(ENCRYPTED_VALUE_PREFIX))
    );
    assert!(encrypted.iter().all(|(_, value)| {
        let encoded = value.strip_prefix(ENCRYPTED_VALUE_PREFIX).unwrap();
        !encoded.contains('=') && !encoded.contains('+') && !encoded.contains('/')
    }));
    assert_ne!(encrypted[0].1, encrypted[1].1);
    let encrypted_source = std::str::from_utf8(&document.source).unwrap();
    assert!(encrypted_source.starts_with("# heading\n"));
    assert!(encrypted_source.contains(" # keep\nSECOND=\"xsec:"));

    decrypt_environment_document(&mut document, &xsec).unwrap();

    assert_eq!(
        parse_environment(&document.source).unwrap(),
        vec![
            ("FIRST".to_owned(), "one".to_owned()),
            ("SECOND".to_owned(), "one".to_owned())
        ]
    );
    assert!(document.source.starts_with(b"# heading\n"));
}

#[tokio::test]
async fn encryption_is_idempotent_for_encrypted_values() {
    let (_directory, xsec) = create_test_xsec().await;
    let mut document = EnvDocument::parse(Zeroizing::new(b"KEY=value\n".to_vec())).unwrap();
    encrypt_environment_document(&mut document, &xsec).unwrap();
    let encrypted = document.source.clone();

    encrypt_environment_document(&mut document, &xsec).unwrap();

    assert_eq!(document.source, encrypted);
}

#[tokio::test]
async fn encrypted_value_is_bound_to_its_key() {
    let (_directory, xsec) = create_test_xsec().await;
    let encrypted = encrypt_environment_value("FIRST", b"secret", &xsec).unwrap();
    let encrypted = std::str::from_utf8(&encrypted).unwrap();

    assert!(matches!(
        decrypt_environment_value("SECOND", encrypted, &xsec),
        Err(CliError::InvalidEncryptedVariable(key)) if key == "SECOND"
    ));
}

#[tokio::test]
async fn atomic_update_creates_a_missing_environment_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(".xsec");

    atomic_replace_if_unchanged(&path, b"KEY=value\n".to_vec(), None)
        .await
        .unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), b"KEY=value\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn atomic_update_does_not_replace_a_concurrently_created_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(".xsec");
    std::fs::write(&path, b"EXISTING=value\n").unwrap();

    assert!(matches!(
        atomic_replace_if_unchanged(&path, b"KEY=value\n".to_vec(), None).await,
        Err(CliError::ConcurrentModification(changed)) if changed == path.display().to_string()
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"EXISTING=value\n");
}

#[tokio::test]
async fn protected_inputs_preserve_plaintext_values() {
    let (_directory, xsec) = create_test_xsec().await;
    let encrypted = encrypt_environment_value("SECRET", b"secret", &xsec).unwrap();
    let mut source = b"PUBLIC=visible\nSECRET=".to_vec();
    source.extend_from_slice(&encode_environment_value(&encrypted).unwrap());
    source.push(b'\n');
    let mut document = EnvDocument::parse(Zeroizing::new(source.clone())).unwrap();

    let environment =
        decrypt_environment_values(&EnvDocument::parse(Zeroizing::new(source)).unwrap(), &xsec)
            .unwrap();
    assert_eq!(
        environment,
        vec![
            ("PUBLIC".to_owned(), "visible".to_owned()),
            ("SECRET".to_owned(), "secret".to_owned())
        ]
    );

    decrypt_environment_document(&mut document, &xsec).unwrap();
    assert_eq!(
        parse_environment(&document.source).unwrap(),
        vec![
            ("PUBLIC".to_owned(), "visible".to_owned()),
            ("SECRET".to_owned(), "secret".to_owned())
        ]
    );
}

#[test]
fn rejects_legacy_whole_document_ciphertext() {
    assert!(matches!(
        load_environment_document(b"XSecCT legacy ciphertext".to_vec()),
        Err(CliError::InvalidEnvironment)
    ));
}

#[test]
fn parses_environment_without_mutating_process_environment() {
    let environment = parse_environment(b"FIRST=one\nSECOND=\"two words\"\n").unwrap();
    assert_eq!(
        environment,
        vec![
            ("FIRST".to_owned(), "one".to_owned()),
            ("SECOND".to_owned(), "two words".to_owned())
        ]
    );
}

#[test]
fn rejects_duplicate_environment_variables() {
    assert!(matches!(
        parse_environment(b"DUPLICATE=one\nDUPLICATE=two\n"),
        Err(CliError::DuplicateVariable(key)) if key == "DUPLICATE"
    ));
}

#[test]
fn strips_one_terminal_line_ending_from_stdin_password() {
    let mut password = b"secret\r\n".to_vec();
    strip_line_ending(&mut password);
    assert_eq!(password, b"secret");
}
