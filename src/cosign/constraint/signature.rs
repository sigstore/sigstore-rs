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

//! Structs that can be used to sign a [`crate::cosign::SignatureLayer`]

use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use tracing::warn;
use zeroize::Zeroizing;

use crate::{
    cosign::SignatureLayer,
    crypto::{signing_key::SigStoreKeyPair, SigStoreSigner, SigningScheme},
    errors::{Result, SigstoreError},
};

use super::Constraint;

/// Sign the [`SignatureLayer`] with the given [`SigStoreSigner`].
/// This constraint must be the last one to applied to a [`SignatureLayer`],
/// since all the plaintext is defined.
#[derive(Debug)]
pub struct PrivateKeySigner {
    key: SigStoreSigner,
}

impl PrivateKeySigner {
    /// Create a new [PrivateKeySigner] with given raw PEM data of a
    /// private key.
    pub fn new_with_raw(
        key_raw: Zeroizing<Vec<u8>>,
        password: Zeroizing<Vec<u8>>,
        signing_scheme: &SigningScheme,
    ) -> Result<Self> {
        let signer = match password.is_empty() {
            true => SigStoreKeyPair::from_pem(&key_raw),
            false => SigStoreKeyPair::from_encrypted_pem(&key_raw, &password),
        }
        .map_err(|e| SigstoreError::ApplyConstraintError(e.to_string()))?
        .to_sigstore_signer(signing_scheme)
        .map_err(|e| SigstoreError::ApplyConstraintError(e.to_string()))?;

        Ok(Self { key: signer })
    }

    pub fn new_with_signer(signer: SigStoreSigner) -> Self {
        Self { key: signer }
    }
}

impl Constraint for PrivateKeySigner {
    fn add_constraint(&self, signature_layer: &mut SignatureLayer) -> Result<bool> {
        if signature_layer.signature.is_some() {
            warn!(signature = ?signature_layer.signature, "already has signature");
            return Ok(false);
        }
        signature_layer.raw_data = serde_json::to_vec(&signature_layer.simple_signing)?;
        let sig = self.key.sign(&signature_layer.raw_data)?;
        let sig_base64 = BASE64_STD_ENGINE.encode(sig);
        signature_layer.signature = Some(sig_base64);
        Ok(true)
    }
}
