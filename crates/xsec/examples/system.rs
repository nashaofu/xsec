use xsec::{XSec, XSecError, XSecFileStorage, XSecResult, XSecSystemProtector};

#[tokio::main]
async fn main() -> XSecResult<()> {
    let storage = XSecFileStorage::new("target/system.xsec.meta");
    let protector = XSecSystemProtector::new("xsec-example-system");

    if std::env::args().any(|arg| arg == "--delete") {
        protector.delete().await?;
        println!("Deleted the system protector key.");
        return Ok(());
    }

    let mut xsec = XSec::new();
    xsec.load(storage).await?;

    let result = if xsec.is_initialized() {
        xsec.unlock(&protector).await
    } else {
        xsec.create(&protector).await
    };
    if let Err(error) = result {
        match error {
            XSecError::WindowsHelloNotSupported
            | XSecError::WindowsHelloNotConfigured
            | XSecError::SystemAuthenticationNotConfigured
            | XSecError::SystemProtectorUnavailable => {
                println!(
                    "System protector is unavailable: configure the platform authentication service before running this example."
                );
                return Ok(());
            }
            XSecError::SystemKeyNotFound => {
                println!(
                    "The Linux system key expired with the previous process; unlock with another protector or recreate the example storage."
                );
                return Ok(());
            }
            error => return Err(error),
        }
    }

    let ciphertext = xsec.encrypt_with_aad(b"secret data", b"example:record")?;
    let plaintext = xsec.decrypt_with_aad(&ciphertext, b"example:record")?;
    println!("Decrypted: {} bytes", plaintext.len());

    Ok(())
}
