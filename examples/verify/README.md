This is a simple example program that shows how to use the
`sigstore::verify` function.

The program currently support verification of a signed image by using a cosign
public key. This key is read from the local filesystem.

The program allows also to use annotation, in the same way as `cosign verify -a key=value`
does.

The program prints to the standard output all the Simple Signing objects that
have been successfully verified.
