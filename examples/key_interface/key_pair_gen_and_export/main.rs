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

use anyhow::Result;
use sigstore::crypto::SigningScheme;

const PASSWORD: &str = "example password";

fn main() -> Result<()> {
    let signer = SigningScheme::ECDSA_P256_SHA256_ASN1.create_signer()?;
    println!("Created a new key pair for ECDSA_P256_SHA256_ASN1.\n");

    let key_pair = signer.to_sigstore_keypair()?;
    println!("Derived `SigStoreKeyPair` from the `SigStoreSigner`.\n");

    let pub_pem = key_pair.public_key_to_pem()?;
    println!("Exported the public key in PEM format.");
    println!("public key:\n {}", pub_pem);

    let pub_der = key_pair.public_key_to_der()?;
    println!("Exported the public key in DER format.");
    println!("public key:\n {:x?}", pub_der);

    let pri_pem = key_pair.private_key_to_pem()?;
    println!("Exported the private key in PEM format.");
    println!("private key:\n {}", *pri_pem);

    let pri_der = key_pair.private_key_to_der()?;
    println!("Exported the private key in DER format.");
    println!("private key:\n {:x?}", *pri_der);

    let encrypted_pri_pem = key_pair.private_key_to_encrypted_pem(PASSWORD.as_bytes())?;
    println!("Exported the encrypted private key in PEM format.");
    println!("private key:\n {}", *encrypted_pri_pem);

    Ok(())
}
