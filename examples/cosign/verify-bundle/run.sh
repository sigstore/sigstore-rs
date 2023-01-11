BLOB="artifact.txt"
BUNDLE="artifact.bundle"

echo -e "\nGenerate the blob to be signed"
echo something > $BLOB

echo -e "\nSign the artifact.txt file using sign-blob"
COSIGN_EXPERIMENTAL=1 cosign sign-blob --bundle=$BUNDLE $BLOB

echo -e "\nVerify using cosign. TODO: remove this later"
cosign verify-blob --bundle=$BUNDLE $BLOB

echo -e "\nRun examples/cosign/verify-bundle"
cargo run --example verify-bundle -- \
    --rekor-pub-key ~/.sigstore/root/targets/rekor.pub \
    --bundle $BUNDLE \
    $BLOB
