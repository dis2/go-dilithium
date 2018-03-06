package dilithium

type SK [SK_SIZE_PACKED]byte
type PK [PK_SIZE_PACKED]byte
type Sig [SIG_SIZE_PACKED]byte

// Generate a new keypair from a given secret seed. If seed is nil, CSPRNG will
// be used and seed will be returned you can use in the future to get same keys.
func KeyPair(seed []byte) (pk PK, sk SK, rseed []byte) {
	rseed = crypto_sign_keypair(seed, &pk, &sk)
	return
}

// Return raw byte pointer representing the secret key
func (k *SK) Bytes() *[SK_SIZE_PACKED]byte {
	return (*[SK_SIZE_PACKED]byte)(k)
}

// Sign the message m, and return it with signature attached.
// The message will grow by PK_SIZE_PACKED, the original m buffer is untouched.
func (k *SK) Seal(m []byte) []byte {
	return crypto_sign(m, k.Bytes())
}

// Sign the message m, and return the detached signature.
func (k *SK) Sign(m []byte) (sig Sig) {
	return crypto_sign_detached(&sig, m, k)
}

// Return raw byte pointer representing the public key
func (k *PK) Bytes() *[PK_SIZE_PACKED]byte {
	return (*[PK_SIZE_PACKED]byte)(k)
}

// Verify signature on m, and return it with signature data stripped.
// If verification fails, returns nil.
func (k *PK) Open(m []byte) []byte {
	return crypto_sign_open(m, k.Bytes())
}

// Check if message m is signed with valid signature in sig.
func (k *PK) Verify(m []byte, sig *Sig) bool {
	return crypto_verify_detached(sig.Bytes(), m, k)
}

// Return pointer to bytes representing the signature.
func (sig *Sig) Bytes() {
	return (*[SIG_SIZE_PACKED]byte)(sig)
}
