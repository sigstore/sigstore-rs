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

use anyhow::{bail, Result};
use sigstore::crypto::{
    signing_key::{ecdsa::ECDSAKeys, SigStoreKeyPair},
    CosignVerificationKey, SigningScheme,
};

const PASSWORD: &str = "password";

const ECDSA_P256_ASN1_PUBLIC_PEM: &[u8] = include_bytes!("./ECDSA_P256_ASN1_PUBLIC_PEM.pub");
const ECDSA_P256_ASN1_PUBLIC_DER: &[u8] = include_bytes!("./ECDSA_P256_ASN1_PUBLIC_DER.pub");
const ECDSA_P256_ASN1_PRIVATE_PEM: &[u8] = include_bytes!("./ECDSA_P256_ASN1_PRIVATE_PEM.key");
const ECDSA_P256_ASN1_PRIVATE_DER: &[u8] = include_bytes!("./ECDSA_P256_ASN1_PRIVATE_DER.key");
const ECDSA_P256_ASN1_ENCRYPTED_PRIVATE_PEM: &[u8] =
    include_bytes!("./ECDSA_P256_ASN1_ENCRYPTED_PRIVATE_PEM.key");

fn main() -> Result<()> {
    let _ = CosignVerificationKey::from_pem(ECDSA_P256_ASN1_PUBLIC_PEM, &SigningScheme::default())?;
    println!("Imported PEM encoded public key as CosignVerificationKey using ECDSA_P256_ASN1_PUBLIC_PEM as verification algorithm.");

    let _ = CosignVerificationKey::from_der(ECDSA_P256_ASN1_PUBLIC_DER, &SigningScheme::default())?;
    println!("Imported DER encoded public key as CosignVerificationKey using ECDSA_P256_ASN1_PUBLIC_PEM as verification algorithm.");

    let _ = CosignVerificationKey::try_from_pem(ECDSA_P256_ASN1_PUBLIC_PEM)?;
    println!("Imported PEM encoded public key as CosignVerificationKey.");

    let _ = CosignVerificationKey::try_from_der(ECDSA_P256_ASN1_PUBLIC_DER)?;
    println!("Imported DER encoded public key as CosignVerificationKey.");

    let _ = SigStoreKeyPair::from_pem(ECDSA_P256_ASN1_PRIVATE_PEM)?;
    println!("Imported PEM encoded private key as SigStoreKeyPair.");

    let _ = ECDSAKeys::from_pem(ECDSA_P256_ASN1_PRIVATE_PEM)?;
    println!("Imported PEM encoded private key as ECDSAKeys.");

    let _ = SigStoreKeyPair::from_der(ECDSA_P256_ASN1_PRIVATE_DER)?;
    println!("Imported DER encoded private key as SigStoreKeyPair.");

    let _ = ECDSAKeys::from_der(ECDSA_P256_ASN1_PRIVATE_DER)?;
    println!("Imported DER encoded private key as ECDSAKeys.");

    let key_pair = SigStoreKeyPair::from_encrypted_pem(
        ECDSA_P256_ASN1_ENCRYPTED_PRIVATE_PEM,
        PASSWORD.as_bytes(),
    )?;
    println!("Imported encrypted PEM encoded private key as SigStoreKeyPair.");

    let ecdsa_key_pair =
        ECDSAKeys::from_encrypted_pem(ECDSA_P256_ASN1_ENCRYPTED_PRIVATE_PEM, PASSWORD.as_bytes())?;
    println!("Imported encrypted PEM encoded private key as ECDSAKeys.");

    let _ = ecdsa_key_pair.to_sigstore_signer()?;
    println!("Converted ECDSAKeys to SigStoreSigner.");

    match key_pair {
        SigStoreKeyPair::ECDSA(inner) => {
            inner.to_sigstore_signer()?;
            println!("Converted SigStoreKeyPair to SigStoreSigner.");
        }
        _ => bail!("Wrong key pair type."),
    }

    Ok(())
}
