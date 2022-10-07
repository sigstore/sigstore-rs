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
use sigstore::crypto::{Signature, SigningScheme};

const DATA_TO_BE_SIGNED: &str = "this is an example data to be signed";

fn main() -> Result<()> {
    let signer = SigningScheme::ECDSA_P256_SHA256_ASN1.create_signer()?;
    println!("Created a new key pair for ECDSA_P256_SHA256_ASN1.\n");

    let signature_data = signer.sign(DATA_TO_BE_SIGNED.as_bytes())?;
    println!("Signed the example data.");
    println!("Data: {}", DATA_TO_BE_SIGNED);
    println!("Signature: {:x?}\n", &signature_data);

    let verification_key = signer.to_verification_key()?;
    println!("Derive verification key from the signer.\n");

    println!("Verifying the signature of the example data...");
    match verification_key.verify_signature(
        Signature::Raw(&signature_data),
        DATA_TO_BE_SIGNED.as_bytes(),
    ) {
        Ok(_) => {
            println!("Verification Succeeded.");
            Ok(())
        }
        Err(e) => Err(anyhow!("Verifycation failed: {}", e)),
    }
}
