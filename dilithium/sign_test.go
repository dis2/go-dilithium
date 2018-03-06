
// +build fuzz

package dilithium

import "testing"
import "bytes"
import "math/rand"

func make_error(dup []byte) int {
	pos := rand.Intn(len(dup))
	dup[pos] ^= 1 << uint((rand.Intn(8)))
	return pos
}

func TestRandomFlips(t *testing.T) {
	var sk [SK_SIZE_PACKED]byte
	var pk [PK_SIZE_PACKED]byte
	crypto_sign_keypair(nil, &pk, &sk)
	msg := []byte("")
	signed := crypto_sign(msg, &sk)

	dup := make([]byte, len(signed))
	copy(dup, signed)
	if crypto_sign_open(dup, &pk) == nil {
		t.Fatal()
	}
	N := 100000
	faults := 0
	for i := 0; i < N; i++ {
		copy(dup, signed)
		make_error(dup)
		if crypto_sign_open(dup, &pk) != nil {
			faults++
		}
	}
	t.Logf("%d faults out of %d\n", faults, N)
}
