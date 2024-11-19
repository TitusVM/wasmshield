use std::path::Path;
use anyhow::{Error, bail};

/// Verify signatures of WebAssembly binaries (wrapper for the wasmsign2 crate)
pub fn verify(bytes: &[u8], key_path: &Path) -> Result<bool, Error> {
    let public_key = match wasmsign2::PublicKey::from_any_file(key_path) {
        Ok(pub_key) => { pub_key },
        Err(err) => { bail!(err) }
    };

    match public_key.verify(&mut &bytes[..], None) {
        Ok(()) => { Ok(true) }
        Err(err) => { bail!(err) }
    }
}