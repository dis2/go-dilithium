package dilithium

import "testing"
import "bytes"
import "math/rand"

func TestParams(t *testing.T) {
	t.Logf("Current params yield: %d public key size, %d signature size\n", PK_SIZE_PACKED, SIG_SIZE_PACKED)
}

func TestSignVerify(t *testing.T) {
	t.Log("generating keypair")
	var sk [SK_SIZE_PACKED]byte
	var pk [PK_SIZE_PACKED]byte
	crypto_sign_keypair(nil, &pk, &sk)
	msg := []byte("hello")
	t.Log("signing")
	signed := crypto_sign(msg, &sk)
	t.Log("verifying")
	check := crypto_sign_open(signed, &pk)
	if bytes.Compare(check, msg) != 0 {
		t.Fatal("signature verification failed")
	}
}

func TestSignVerify10000(t *testing.T) {
	var sk [SK_SIZE_PACKED]byte
	var pk [PK_SIZE_PACKED]byte
	msg := []byte("hello there")
	for i := 0; i < 10000; i++ {
		crypto_sign_keypair(nil, &pk, &sk)
		msg[0] = byte(i)
		msg[1] = byte(i >> 8)
		msg[2] = byte(i >> 16)
		msg[3] = byte(i >> 24)
		signed := crypto_sign(msg, &sk)
		if crypto_sign_open(signed, &pk) == nil {
			t.Fatal("failed to verify")
		}
	}
}

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
		make_error(dup)
		if crypto_sign_open(dup, &pk) != nil {
			faults++
		}
	}
	t.Logf("%d faults out of %d\n", faults, N)
}
