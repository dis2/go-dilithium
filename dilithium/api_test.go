package dilithium

import "crypto/aes"
import "archive/zip"
import "net/http"
import "testing"
import "strconv"
import "encoding/hex"
import "io/ioutil"
import "io"
import "os"
import "strings"
import "bytes"
import "bufio"
import "fmt"
import "path"

// Golden known answers test data.
var GOLDEN_ZIP = "https://pq-crystals.org/dilithium/data/dilithium-submission-nist-updated.zip"
var GOLDEN_KAT = fmt.Sprintf("PQCsignKAT_%d.rsp", SK_SIZE_PACKED)

func TestParams(t *testing.T) {
	t.Logf("Current params yield: %d public key size, %d signature size\n", PK_SIZE_PACKED, SIG_SIZE_PACKED)
}

func TestSignVerify(t *testing.T) {
	pk, sk, _ := KeyPair(nil)
	msg := []byte("hello")
	sealed := sk.Seal(msg)
	if bytes.Compare(pk.Open(sealed), msg) != 0 {
		t.Fatal("basic signing failed")
	}
}

func TestSignVerifyDetached(t *testing.T) {
	pk, sk, _ := KeyPair(nil)
	msg := []byte("hello")
	sig := sk.Sign(msg)
	t.Logf("detached sig size %d (%d bytes saved)\n", len(sig), SIG_SIZE_PACKED-len(sig))
	if !pk.Verify(msg, sig) {
		t.Fatal("basic detached signing failed")
	}
}

func TestBadSign(t *testing.T) {
	pk, sk, _ := KeyPair(nil)
	msg := []byte("hello")
	sealed := sk.Seal(msg)
	sealed[5] ^= 1
	sealed[6] ^= 1
	sealed[7] ^= 1
	if bytes.Compare(pk.Open(sealed), msg) == 0 {
		t.Fatal("broken signature accepted")
	}
}

func TestBadSignDetached(t *testing.T) {
	pk, sk, _ := KeyPair(nil)
	msg := []byte("hello")
	sig := sk.Sign(msg)
	sig[5] ^= 1
	sig[6] ^= 1
	sig[7] ^= 1

	if pk.Verify(msg, sig) {
		t.Fatal("broken detached signature accepted")
	}
}


func TestSeed(t *testing.T) {
	pk, sk, seed := KeyPair(nil)
	pk2, sk2, _ := KeyPair(seed)

	if bytes.Compare(pk.Bytes()[:], pk2.Bytes()[:]) != 0 {
		t.Fatal("pk mismatch")
	}
	if bytes.Compare(sk.Bytes()[:], sk2.Bytes()[:]) != 0 {
		t.Fatal("sk mismatch")
	}
}

// input 48 bytes seed, output 32 bytes seed
func seedNIST(t *testing.T, seed []byte) []byte {
	var key [32]byte
	var V [16]byte
	var temp [48]byte
	var res [32]byte

	incV := func() {
		for j:=15; j>=0; j-- {
			if V[j] == 0xff {
				V[j] = 0
			} else {
				V[j]++
				break
			}
		}
	}

	state, _ := aes.NewCipher(key[:])
	for i := byte(0); i < 3; i++ {
		incV()
		state.Encrypt(temp[16*i:], V[:])
	}
	for i := 0; i < 48; i++ {
		temp[i] ^= seed[i]
	}
	copy(key[:], temp[:32])
	copy(V[:], temp[32:])
	state, _ = aes.NewCipher(key[:])
	incV()
	state.Encrypt(res[0:16], V[:])
	incV()
	state.Encrypt(res[16:32], V[:])
	return res[:]
}

func TestPQCSignKAT(t *testing.T) {
	os.Mkdir("testdata", 0755)
	cached := "testdata/" + path.Base(GOLDEN_ZIP)
	zipfile, err := zip.OpenReader(cached)
	if err != nil {
		t.Logf("Retrieving golden KAT zip from %s", GOLDEN_ZIP)
		resp, _ := http.Get(GOLDEN_ZIP)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		ioutil.WriteFile(cached, body, 0644)
		zipfile, _ = zip.OpenReader(cached)
	}

	var katfile io.ReadCloser
	gotkat := false
	for _, f := range zipfile.File {
		if strings.HasSuffix(f.Name, GOLDEN_KAT) {
			katfile, _ = f.Open()
			gotkat = true
			break
		}
	}


	if !gotkat {
		t.Fatal("failed to get golden KAT data")
	}

	r := bufio.NewReader(katfile)

	smlen := 0
	mlen := 0
	var opk,pk PK
	var osk,sk SK
	var msg []byte
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		fields := strings.Split(line, " ")
		if len(fields) != 3 {
			continue
		}
		val := strings.TrimSpace(fields[2])
		bval := []byte(val)
		hval := make([]byte, hex.DecodedLen(len(bval)))
		hex.Decode(hval, bval)
		switch fields[0] {
		case "smlen":
			smlen, _ = strconv.Atoi(val)
		case "mlen":
			mlen, _ = strconv.Atoi(val)
		case "msg":
			if len(hval) != mlen {
				t.Fatal("mlen != len(msg)")
			}
			msg = hval
			_ = msg
		case "seed": {
			//var seed [32]byte
			if len(hval) != 48 {
				t.Fatal("expected 48 byte seed")
			}
			opk, osk, _ = KeyPair(seedNIST(t,hval))
		}
		case "sk":
			if len(hval) != SK_SIZE_PACKED {
				t.Fatal("sk size mismatch")
			}
			copy(sk.Bytes()[:], hval)
			if bytes.Compare(osk.Bytes()[:], sk.Bytes()[:]) != 0 {
				t.Fatal("sk mismatch")
			}
		case "pk": {
			if len(hval) != PK_SIZE_PACKED {
				t.Fatal("pk size mismatch")
			}
			copy(pk.Bytes()[:], hval)
			if bytes.Compare(opk.Bytes()[:], pk.Bytes()[:]) != 0 {
				t.Fatal("pk mismatch")
			}
		}
		case "sm":
			if len(hval) != smlen {
				t.Fatal("smlen != len(sm)")
			}
			if bytes.Compare(osk.Seal(msg), hval) != 0 {
				t.Fatal("signed data mismatch")
			}
			if pk.Open(hval) == nil {
				t.Fatal("failed to validate")
			}
		}
	}
}

func TestSignVerify1000(t *testing.T) {
	var sk [SK_SIZE_PACKED]byte
	var pk [PK_SIZE_PACKED]byte
	msg := []byte("hello there")
	for i := 0; i < 1000; i++ {
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


