use wasm_bindgen::prelude::*;

use kestrel_crypto::errors::{ChaPolyDecryptError, DecryptError, EncryptError};

#[wasm_bindgen]
pub fn chapoly_encrypt_ietf(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    kestrel_crypto::chapoly_encrypt_ietf(key, nonce, plaintext, aad)
}

#[wasm_bindgen]
pub fn chapoly_decrypt_ietf(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    Ok(
        kestrel_crypto::chapoly_decrypt_ietf(key, nonce, ciphertext, aad)
            .map_err(|e| fmt_error(&e))?,
    )
}

#[wasm_bindgen]
pub fn pass_encrypt(
    mut plaintext: &[u8],
    password: &[u8],
    salt: &[u8],
    file_format: u8,
) -> Result<Vec<u8>, JsValue> {
    let pass_ver = if file_format == 0x20 {
        kestrel_crypto::PassFileFormat::V1
    } else {
        return Err(fmt_error(&"Invalid password file format version"));
    };
    let mut ciphertext: Vec<u8> = Vec::with_capacity(calc_capacity(plaintext.len()));
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| fmt_error(&"Invalid salt length. Must be 32."))?;
    kestrel_crypto::encrypt::pass_encrypt(
        &mut plaintext,
        &mut ciphertext,
        password,
        salt,
        pass_ver,
    )
    .map_err(|e| fmt_error(&e))?;
    Ok(ciphertext)
}

#[wasm_bindgen]
pub fn pass_decrypt(
    mut ciphertext: &[u8],
    password: &[u8],
    file_format: u8,
) -> Result<Vec<u8>, JsValue> {
    let pass_ver = if file_format == 0x20 {
        kestrel_crypto::PassFileFormat::V1
    } else {
        return Err(fmt_error(&"Invalid password file format version"));
    };

    let mut plaintext: Vec<u8> = Vec::with_capacity(calc_capacity(ciphertext.len()));
    kestrel_crypto::decrypt::pass_decrypt(&mut ciphertext, &mut plaintext, password, pass_ver)
        .map_err(|e| fmt_error(&e))?;
    Ok(plaintext)
}

#[wasm_bindgen]
pub fn scrypt(password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, dk_len: usize) -> Vec<u8> {
    kestrel_crypto::scrypt(password, salt, n, r, p, dk_len)
}

#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    kestrel_crypto::sha256(data).to_vec()
}

fn fmt_error(err: &dyn std::any::Any) -> JsValue {
    fn err_msg(name: &str, msg: &str) -> JsValue {
        format!("{}; {}", name, msg).into()
    }

    if let Some(e) = err.downcast_ref::<ChaPolyDecryptError>() {
        err_msg("ChaPolyDecryptError", e.to_string().as_str())
    } else if let Some(e) = err.downcast_ref::<EncryptError>() {
        match e {
            EncryptError::UnexpectedData => {
                err_msg("EncryptError::UnexpectedData", e.to_string().as_str())
            }
            EncryptError::IORead(_) => err_msg("EncryptError::IORead", e.to_string().as_str()),
            EncryptError::IOWrite(_) => err_msg("EncryptError::IOWrite", e.to_string().as_str()),
        }
    } else if let Some(e) = err.downcast_ref::<DecryptError>() {
        match e {
            DecryptError::ChunkLen => err_msg("DecryptError::ChunkLen", e.to_string().as_str()),
            DecryptError::ChaPolyDecrypt => {
                err_msg("DecryptError::ChaPolyDecrypt", e.to_string().as_str())
            }
            DecryptError::UnexpectedData => {
                err_msg("DecryptError::UnexpectedData", e.to_string().as_str())
            }
            DecryptError::IORead(_) => err_msg("DecryptError::IORead", e.to_string().as_str()),
            DecryptError::IOWrite(_) => err_msg("DecryptError::IOWrite", e.to_string().as_str()),
            DecryptError::Other(_) => err_msg("DecryptError::Other", e.to_string().as_str()),
        }
    } else if let Some(e) = err.downcast_ref::<String>() {
        err_msg("ErrorMessage", e.as_str())
    } else if let Some(e) = err.downcast_ref::<&str>() {
        err_msg("ErrorMessage", e)
    } else {
        err_msg("Unknown", "Unknown")
    }
}

fn calc_capacity(len: usize) -> usize {
    len + ((((len / 65536) + 1) * 32) + 128)
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert_eq!(2, 2);
    }
}
