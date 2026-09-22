use secrecy::SecretBox;
use xsec::{XSec, XSecFileStorage, XSecPasswordProtector, XSecResult};

#[tokio::main]
async fn main() -> XSecResult<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("init") => {
            let path = args.next().unwrap_or_else(|| "xsec.data".to_owned());
            let password = args.next().unwrap_or_else(|| "change-me".to_owned());
            let protector =
                XSecPasswordProtector::new(SecretBox::new(Box::new(password.into_bytes())));
            let mut xsec = XSec::new();
            xsec.load(XSecFileStorage::new(path)).await?;
            if xsec.is_initialized() {
                xsec.unlock(&protector).await?;
                println!("XSec storage unlocked");
            } else {
                xsec.create(&protector).await?;
                println!("XSec storage initialized");
            }
        }
        _ => {
            println!("Usage: xsec-cli init [storage-path] [password]");
        }
    }
    Ok(())
}
