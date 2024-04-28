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
    kestrel_crypto::chapoly_decrypt_ietf(key, nonce, ciphertext, aad).map_err(|e| fmt_error(&e))
}

#[wasm_bindgen]
pub fn pass_encrypt(
    mut plaintext: &[u8],
    password: &[u8],
    salt: &[u8],
    file_format: u8,
) -> Result<Vec<u8>, JsValue> {
    let file_format = if file_format == 0x20 {
        kestrel_crypto::PassFileFormat::V1
    } else {
        return Err(fmt_error(&"Invalid password file format version"));
    };
    let mut ciphertext: Vec<u8> = Vec::with_capacity(calc_pass_capacity(plaintext.len()));
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| fmt_error(&"Invalid salt length. Must be 32."))?;
    kestrel_crypto::encrypt::pass_encrypt(
        &mut plaintext,
        &mut ciphertext,
        password,
        salt,
        file_format,
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
    let file_format = if file_format == 0x20 {
        kestrel_crypto::PassFileFormat::V1
    } else {
        return Err(fmt_error(&"Invalid password file format version"));
    };

    let mut plaintext: Vec<u8> = Vec::with_capacity(calc_pass_capacity(ciphertext.len()));
    kestrel_crypto::decrypt::pass_decrypt(&mut ciphertext, &mut plaintext, password, file_format)
        .map_err(|e| fmt_error(&e))?;
    Ok(plaintext)
}

/// Key based encryption
///
/// For ephem_private and payload_key, pass empty slices (Uint8Array) which
/// will be treated as the None option
#[wasm_bindgen]
pub fn key_encrypt(
    mut plaintext: &[u8],
    sender_private: &[u8],
    recipient_public: &[u8],
    ephem_private: &[u8],
    payload_key: &[u8],
    file_format: u8,
) -> Result<Vec<u8>, JsValue> {
    let file_format = if file_format == 0x10 {
        kestrel_crypto::AsymFileFormat::V1
    } else {
        return Err(fmt_error(&"Invalid asymmetric file format version"));
    };

    let sender_private: kestrel_crypto::PrivateKey = sender_private.into();
    let recipient_public: kestrel_crypto::PublicKey = recipient_public.into();
    let ephem_private: Option<kestrel_crypto::PrivateKey> = if ephem_private.is_empty() {
        None
    } else {
        Some(ephem_private.into())
    };

    let payload_key: Option<[u8; 32]> = if payload_key.is_empty() {
        None
    } else {
        Some(
            payload_key
                .try_into()
                .expect("Payload key must be 32 bytes"),
        )
    };

    let mut ciphertext: Vec<u8> = Vec::with_capacity(calc_key_capacity(plaintext.len()));

    kestrel_crypto::encrypt::key_encrypt(
        &mut plaintext,
        &mut ciphertext,
        &sender_private,
        &recipient_public,
        ephem_private.as_ref(),
        payload_key,
        file_format,
    )
    .map_err(|e| fmt_error(&e))?;

    Ok(ciphertext)
}

/// Key based decryption
///
/// The public_key argument must be 32 bytes in length. The resulting public
/// key will be written into the buffer if decryption is successful.
#[wasm_bindgen]
pub fn key_decrypt(
    mut ciphertext: &[u8],
    recipient_private: &[u8],
    file_format: u8,
    public_key: &mut [u8],
) -> Result<Vec<u8>, JsValue> {
    let file_format = if file_format == 0x10 {
        kestrel_crypto::AsymFileFormat::V1
    } else {
        return Err(fmt_error(&"Invalid asymmetric file format version"));
    };

    if public_key.len() != 32 {
        return Err(fmt_error(&"Public key buf must be 32 bytes"));
    }

    let recipient_private: kestrel_crypto::PrivateKey = recipient_private.into();

    let mut plaintext: Vec<u8> = Vec::with_capacity(calc_key_capacity(ciphertext.len()));
    let sender_public_key = kestrel_crypto::decrypt::key_decrypt(
        &mut ciphertext,
        &mut plaintext,
        &recipient_private,
        file_format,
    )
    .map_err(|e| fmt_error(&e))?;
    let sender_public_key = sender_public_key.as_bytes();

    public_key[..32].copy_from_slice(&sender_public_key[..32]);

    Ok(plaintext)
}

#[wasm_bindgen]
pub fn x25519(k: &[u8], u: &[u8]) -> Vec<u8> {
    kestrel_crypto::x25519(k, u).to_vec()
}

#[wasm_bindgen]
pub fn x25519_derive_public(private_key: &[u8]) -> Vec<u8> {
    kestrel_crypto::x25519_derive_public(private_key).to_vec()
}

#[wasm_bindgen]
pub fn scrypt(password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, dk_len: usize) -> Vec<u8> {
    kestrel_crypto::scrypt(password, salt, n, r, p, dk_len)
}

#[wasm_bindgen]
pub fn secure_random(len: usize) -> Vec<u8> {
    kestrel_crypto::secure_random(len)
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

fn calc_pass_capacity(len: usize) -> usize {
    len + ((((len / 65536) + 1) * 32) + 36)
}

fn calc_key_capacity(len: usize) -> usize {
    len + ((((len / 65536) + 1) * 32) + 132)
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert_eq!(2, 2);
    }
}
