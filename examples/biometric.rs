use xsec::{XSec, XSecBiometricProtector, XSecFileStorage, XSecResult};

#[tokio::main]
async fn main() -> XSecResult<()> {
    let storage = XSecFileStorage::new("target/biometric.xsec");
    let protector = XSecBiometricProtector::new("xsec-example-biometric");

    let mut xsec = XSec::new();
    xsec.load(storage).await?;

    if xsec.is_initialized() {
        xsec.unlock(&protector).await?;
    } else {
        xsec.create(&protector).await?;
    }

    let ciphertext = xsec.encrypt_with_aad(b"secret data", b"example:record")?;
    let plaintext = xsec.decrypt_with_aad(&ciphertext, b"example:record")?;
    println!("Decrypted: {} bytes", plaintext.len());

    Ok(())
}
