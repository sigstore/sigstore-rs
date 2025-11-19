BLOB="README.md"
BUNDLE="artifact.bundle"

echo -e "\nSign README.md file using sign-blob"
cosign sign-blob --bundle=$BUNDLE $BLOB

echo -e "\nRun examples/cosign/verify-bundle"
cargo run --example verify-bundle -- \
    --rekor-pub-key ~/.sigstore/root/targets/rekor.pub \
    --bundle $BUNDLE \
    $BLOB
