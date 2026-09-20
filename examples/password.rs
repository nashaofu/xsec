use secrecy::SecretBox;
use xsec::{XSec, XSecFileStorage, XSecPasswordProtector, XSecResult};

#[tokio::main]
async fn main() -> XSecResult<()> {
    let storage = XSecFileStorage::new("target/example.xsec");
    let password = SecretBox::new(Box::new(b"correct horse battery staple".to_vec()));
    let protector = XSecPasswordProtector::new(password);

    let xsec = if storage.exists().await? {
        let mut xsec = XSec::open(storage).await?;
        // xsec.add_key_protector(&protector).await?;
        xsec.unlock(&protector).await?;
        xsec
    } else {
        let mut xsec = XSec::create(storage).await?;
        xsec.add_key_protector(&protector).await?;
        xsec.unlock(&protector).await?;
        xsec
    };

    let plaintext = "secret data";
    println!("Plaintext: {}", plaintext);
    let ciphertext = xsec.encrypt_with_aad(plaintext.as_bytes(), b"sdasdas")?;
    println!("Ciphertext: {:?}", ciphertext);
    let decrypted = xsec.decrypt_with_aad(&ciphertext, b"sdasdas")?;
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    Ok(())
}
