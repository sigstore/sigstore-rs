pub mod proof_verification;
pub mod rfc6962;

#[cfg(test)]
mod testdata_tests;

#[cfg(any(
    feature = "verify",
    feature = "sign",
    feature = "sigstore-trust-root",
    feature = "rekor"
))]
use crate::errors::SigstoreError;
#[cfg(any(
    feature = "verify",
    feature = "sign",
    feature = "sigstore-trust-root",
    feature = "rekor"
))]
use crate::errors::SigstoreError::UnexpectedError;
#[cfg(any(
    feature = "verify",
    feature = "sign",
    feature = "sigstore-trust-root",
    feature = "rekor"
))]
use digest::Output;
pub use proof_verification::MerkleProofError;
pub(crate) use proof_verification::MerkleProofVerifier;
pub(crate) use rfc6962::{Rfc6269Default, Rfc6269HasherTrait};

/// Many rekor models have hex-encoded hashes, this functions helps to avoid repetition.
#[cfg(any(
    feature = "verify",
    feature = "sign",
    feature = "sigstore-trust-root",
    feature = "rekor"
))]
pub(crate) fn hex_to_hash_output(
    h: impl AsRef<[u8]>,
) -> Result<Output<Rfc6269Default>, SigstoreError> {
    hex::decode(h)
        .map_err(Into::into)
        .and_then(|h| {
            <[u8; 32]>::try_from(h.as_slice()).map_err(|err| UnexpectedError(format!("{err:?}")))
        })
        .map(Into::into)
}
