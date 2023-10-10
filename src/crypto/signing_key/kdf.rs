//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Key Derivation Function for Sigstore
//!
//! This is the Rust version of KDF used in Sigstore.
//! Please refer to <https://github.com/theupdateframework/go-tuf/blob/master/encrypted/encrypted.go>
//! for golang version.

use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use crypto_secretbox::aead::{AeadMut, KeyInit};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::errors::*;

/// Salt bit length used in scrypt algorithm.
pub const SALT_SIZE: u32 = 32;

/// KDF name for scrypt.
pub const NAME_SCRYPT: &str = "scrypt";

/// Scrypt algorithm parameter log2(n)
pub const SCRYPT_N: u32 = 32768;

/// Scrypt algorithm parameter r
pub const SCRYPT_R: u32 = 8;

/// Scrypt algorithm parameter p
pub const SCRYPT_P: u32 = 1;

/// Secret box name
pub const NAME_SECRET_BOX: &str = "nacl/secretbox";

/// Key length for secretbox
pub const BOX_KEY_SIZE: usize = 32;

/// Nonce length for secretbox
pub const BOX_NONCE_SIZE: u32 = 24;

/// Parameters for scrypt algorithm.
#[derive(Serialize, Deserialize)]
pub struct ScryptParams {
    #[serde(rename = "N")]
    n: u32,
    r: u32,
    p: u32,
}

/// Key Derivation Function.
/// Using scrypt algorithm from a password.
#[derive(Serialize, Deserialize)]
struct ScryptKDF {
    name: String,
    params: ScryptParams,
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    salt: Vec<u8>,
}

/// Help to serialize `salt` to base64
fn to_base64<S>(v: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&BASE64_STD_ENGINE.encode(v))
}

/// Help to deserialize `salt` from base64
fn from_base64<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = <String>::deserialize(deserializer)?;
    BASE64_STD_ENGINE
        .decode(s)
        .map_err(serde::de::Error::custom)
}

impl Default for ScryptKDF {
    /// Create a new Key derivation function object
    fn default() -> Self {
        let salt = generate_random(SALT_SIZE);
        Self {
            name: NAME_SCRYPT.into(),
            params: ScryptParams {
                n: SCRYPT_N,
                r: SCRYPT_R,
                p: SCRYPT_P,
            },
            salt,
        }
    }
}

impl ScryptKDF {
    /// Derivate a new key from the given password
    fn key(&self, password: &[u8]) -> Result<Vec<u8>> {
        let log_n = (self.params.n as f64).log2() as u8;
        let params = scrypt::Params::new(
            log_n,
            self.params.r,
            self.params.p,
            scrypt::Params::RECOMMENDED_LEN,
        )?;
        let mut res = vec![0; BOX_KEY_SIZE];
        scrypt::scrypt(password, &self.salt, &params, &mut res)?;
        Ok(res)
    }

    /// Check whether the given params is as the default,
    /// to avoid a DoS attack.
    fn check_params(&self) -> Result<()> {
        match self.params.n == SCRYPT_N && self.params.r == SCRYPT_R && self.params.p == SCRYPT_P {
            true => Ok(()),
            false => Err(SigstoreError::PrivateKeyDecryptError(
                "Unexpected kdf parameters".into(),
            )),
        }
    }
}

/// Secretbox is used to seal the given secret
#[derive(Serialize, Deserialize)]
struct SecretBoxCipher {
    name: String,
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    nonce: Vec<u8>,
    #[serde(skip)]
    encrypted: bool,
}

impl Default for SecretBoxCipher {
    fn default() -> Self {
        let nonce = generate_random(BOX_NONCE_SIZE);
        Self {
            name: NAME_SECRET_BOX.into(),
            nonce,
            encrypted: false,
        }
    }
}

impl SecretBoxCipher {
    /// Seal the plaintext using the key and nonce.
    fn encrypt(&mut self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if self.encrypted {
            return Err(SigstoreError::PrivateKeyEncryptError(
                "Encrypt must only be called once for each cipher instance".into(),
            ));
        }
        self.encrypted = true;
        let nonce = crypto_secretbox::Nonce::from_slice(&self.nonce);
        let key = crypto_secretbox::Key::from_slice(key);

        let mut cipher = crypto_secretbox::XSalsa20Poly1305::new(key);
        cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| SigstoreError::PrivateKeyEncryptError(e.to_string()))
    }

    /// Unseal the ciphertext using the key
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let nonce = crypto_secretbox::Nonce::from_slice(&self.nonce);
        let key = crypto_secretbox::Key::from_slice(key);

        let mut cipher = crypto_secretbox::XSalsa20Poly1305::new(key);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| SigstoreError::PrivateKeyEncryptError(e.to_string()))
    }
}

/// `Data` is all content of a encrypted private key.
#[derive(Serialize, Deserialize)]
struct Data {
    kdf: ScryptKDF,
    cipher: SecretBoxCipher,
    #[serde(
        rename = "ciphertext",
        serialize_with = "to_base64",
        deserialize_with = "from_base64"
    )]
    cipher_text: Vec<u8>,
}

/// Generate a random Vec<u8> of given length.
fn generate_random(len: u32) -> Vec<u8> {
    let mut res = Vec::new();
    for _ in 0..len {
        res.push(rand::thread_rng().gen());
    }
    res
}

/// Encrypt the given plaintext using a derived key from
/// password. In sigstore, it is used to encrypt the
/// private key.
pub fn encrypt(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let kdf = ScryptKDF::default();

    let key = kdf.key(password)?;
    let mut box_cipher = SecretBoxCipher::default();
    let cipher_text = box_cipher.encrypt(plaintext, &key)?;

    let data = Data {
        kdf,
        cipher: box_cipher,
        cipher_text,
    };

    let res = serde_json::to_vec(&data)?;
    Ok(res)
}

/// Encrypt the given plaintext using a derived key from
/// password. In sigstore, it is used to decrypt the
/// private key.
pub fn decrypt(ciphertext: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let data: Data = serde_json::from_slice(ciphertext)?;
    if data.cipher.name != NAME_SECRET_BOX {
        return Err(SigstoreError::PrivateKeyDecryptError(format!(
            "Unknown cipher name: {}",
            data.cipher.name
        )));
    }

    if data.kdf.name != NAME_SCRYPT {
        return Err(SigstoreError::PrivateKeyDecryptError(format!(
            "Unknown kdf name: {}",
            data.kdf.name
        )));
    }

    data.kdf.check_params()?;

    let key = data.kdf.key(password)?;
    data.cipher.decrypt(&data.cipher_text, &key)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use crate::crypto::signing_key::kdf::Data;

    /// This test will firstly deserialize the given KDF
    /// payload generated from cosign in golang, and then
    /// serialize the generated object into a new string.
    #[test]
    fn serde_kdf() {
        let input_json = json!({
          "kdf": {
            "name": "scrypt",
            "params": {
              "N": 32768u32,
              "r": 8u32,
              "p": 1u32
            },
            "salt": "+QseLb/O/0j2dG201MALNSv2xLcclv6UvpXZVvXGT0k=",
          },
          "cipher": {
            "name": "nacl/secretbox",
            "nonce": "B5zH5d9AwoPkgaPAwIgpnft2BO6HZM/j",
          },
          "ciphertext": "RQPqIJtoWjlVC49xXNG+zfkGrJF3DWIhdRArI0XeTjGx04QzjAAeybGgW4T9JWKuYYe49NIZCEOD2G8cisMJ9KXHPaxT6Q/lLa8XrkavRrzkaD3xj8tc2AAntvUz8OACtH3zmimeFLr+EtecDb/UNjNFCtW1SlIh6DsfTsbBL67uQqLrFQMW8r70SvsZLkXV8mFhMsKyVryWlQ==",
        });
        let data: Data =
            serde_json::from_value(input_json.clone()).expect("Cannot deserialize json Data");
        let actual_json = serde_json::to_value(data).expect("Cannot serialize Data back to JSON");
        assert_json_eq!(input_json, actual_json);
    }
}
