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

use anyhow::{anyhow, Result};
use sigstore::crypto::{
    signing_key::{SigStoreSigner, SigningScheme},
    CosignVerificationKey, Signature, SignatureDigestAlgorithm,
};
use x509_parser::nom::AsBytes;

const DATA_TO_BE_SIGNED: &str = "this is an example data to be signed";
const PASSWORD: &str = "example password";

fn main() -> Result<()> {
    let signer = SigStoreSigner::new(SigningScheme::ECDSA_P256_SHA256_ASN1)?;
    println!("Created a new key pair for ECDSA_P256_SHA256_ASN1.\n");

    let signature_data = signer.sign(DATA_TO_BE_SIGNED.as_bytes())?;
    println!("Signed the example data.");
    println!("Data: {}", DATA_TO_BE_SIGNED);
    println!("Signature: {:x?}\n", &signature_data);

    let private_key = signer.private_key_to_encrypted_pem(PASSWORD.as_bytes())?;
    println!("Exported the encrypted private key in PEM.");
    println!("Encrypted private key in PEM format:");
    println!("{}\n", *private_key);

    let pub_key = signer.public_key_to_pem()?;
    println!("Exportd the public key of the key pair as PEM format.");
    println!("Public key in PEM format:");
    println!("{}\n", &pub_key);

    let verify_key =
        CosignVerificationKey::from_pem(pub_key.as_bytes(), SignatureDigestAlgorithm::Sha256)?;
    println!("Imported the public key.\n");

    println!("Verifying the signature of the example data...");
    match verify_key.verify_signature(
        Signature::Raw(signature_data.as_bytes()),
        DATA_TO_BE_SIGNED.as_bytes(),
    ) {
        Ok(_) => {
            println!("Verification Succeeded.");
            Ok(())
        }
        Err(e) => Err(anyhow!("Verifycation failed: {}", e)),
    }
}
