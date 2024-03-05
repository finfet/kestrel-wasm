use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn chapoly_encrypt_ietf(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8]
) -> Vec<u8> {
    kestrel_crypto::chapoly_encrypt_ietf(key, nonce, plaintext, aad)
}

#[wasm_bindgen]
pub fn chapoly_decrypt_ietf(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    Ok(kestrel_crypto::chapoly_decrypt_ietf(
        key, nonce, ciphertext, aad,
    ).map_err(|e| format_error(&e, "ChaPolyDecryptError", e.to_string().as_str()))?)
}

#[wasm_bindgen]
pub fn scrypt(password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, dk_len: usize) -> Vec<u8> {
    kestrel_crypto::scrypt(password, salt, n, r, p, dk_len)
}

fn format_error<E: std::error::Error>(err: &E, name: &str, message: &str) -> JsValue {
    format!("{}: {}", name, message).into()
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert_eq!(2, 2);
    }
}
