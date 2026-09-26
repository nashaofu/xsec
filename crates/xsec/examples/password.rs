use secrecy::SecretBox;
use xsec::{XSec, XSecFileStorage, XSecPasswordProtector, XSecResult};

#[tokio::main]
async fn main() -> XSecResult<()> {
    let storage = XSecFileStorage::new("target/example.xsec.keys");
    let password = SecretBox::new(Box::new(b"correct horse battery staple".to_vec()));
    let protector = XSecPasswordProtector::new(password);

    let mut xsec = XSec::new();
    xsec.load(storage).await?;
    if xsec.is_initialized() {
        xsec.unlock(&protector).await?;
    } else {
        xsec.create(&protector).await?;
    }

    let plaintext = "secret data";
    println!("Plaintext: {}", plaintext);
    let ciphertext = xsec.encrypt_with_aad(plaintext.as_bytes(), b"sdasdas")?;
    println!("Ciphertext: {:?}", ciphertext);
    let decrypted = xsec.decrypt_with_aad(&ciphertext, b"sdasdas")?;
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    Ok(())
}
