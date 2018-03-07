// Package dilithium implements experimental post-quantum digital signatures.
// https://eprint.iacr.org/2017/633
//
// The algorithm is only a submitted NIST candidate, and not standardized.
// It's not recommended to use Dilithium in production yet, with the possible
// exception of attaching it as accompanying signature to a classic scheme, such
// as Ed25519.
package dilithium

// SK is the secret key.
type SK [SK_SIZE_PACKED]byte

// PK is the public key.
type PK [PK_SIZE_PACKED]byte

// KeyPair will be created from the given secret seed. If seed is `nil`,
// CSPRNG will be used. Returns the keys and the seed value ultimately used to
// generate those.
func KeyPair(seed []byte) (publicKey PK, secretKey SK, usedSeed []byte) {
	rseed = crypto_sign_keypair(seed, publicKey.Bytes(), secretKey.Bytes())
	return
}

// Bytes buffer representing the secret key.
func (k *SK) Bytes() (rawSecretKeyBytes *[SK_SIZE_PACKED]byte) {
	return (*[SK_SIZE_PACKED]byte)(k)
}

// Seal the message in m.
// New buffer with original message copy with signature attached is returned.
func (k *SK) Seal(message []byte) (sealedMessage []byte) {
	return crypto_sign(message, k.Bytes())
}

// Sign the message, and return a detached signature. Detached signatures are
// variable sized, but never larger than SIG_SIZE_PACKED.
func (k *SK) Sign(message []byte) (signature []byte) {
	var sig [SIG_SIZE_PACKED]byte
	return crypto_sign_detached(&sig, message, k.Bytes())
}

// Bytes returns the raw byte pointer representing the public key.
func (k *PK) Bytes() (rawPublicKeyBytes *[PK_SIZE_PACKED]byte) {
	return (*[PK_SIZE_PACKED]byte)(k)
}

// Open the sealed message m. Returns the original message, with signature data
// stripped. Or nil if the signature is invalid.
func (k *PK) Open(sealedMessage []byte) (originalMessage []byte {
	return crypto_sign_open(sealedMessega, k.Bytes())
}

// Verify if the message is signed with a valid signature.
func (k *PK) Verify(message []byte, signature []byte) bool {
	return crypto_verify_detached(signature, message, k.Bytes())
}


