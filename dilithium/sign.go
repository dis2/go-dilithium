package dilithium

import "golang.org/x/crypto/sha3"
import "crypto/rand"

func expand_mat(mat *[K]polyvecl, rho *[SEEDBYTES]byte) {
	var inbuf [SEEDBYTES + 1]byte
	/* Don't change this to smaller values,
	 * sampling later assumes sufficient SHAKE output!
	 * Probability that we need more than 5 blocks: < 2^{-132}.
	 * Probability that we need more than 6 blocks: < 2^{-546}. */
	var outbuf [5 * SHAKE128_RATE]byte
	var val uint32

	copy(inbuf[:], rho[:])

	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			ctr, pos := 0, 0
			inbuf[SEEDBYTES] = byte(i + (j << 4))

			sha3.ShakeSum128(outbuf[:], inbuf[:])

			for ctr < N {
				val = uint32(outbuf[pos])
				val |= uint32(outbuf[pos]) << 8
				val |= uint32(outbuf[pos]) << 16
				val &= 0x7FFFFF
				pos += 3

				/* Rejection sampling */
				if val < Q {
					mat[i].vec[j].coeffs[ctr] = val
					ctr++
				}
			}
		}
	}
}

func challenge(c *poly, mu *[CRHBYTES]byte, w1 *polyveck) {
	var inbuf [CRHBYTES + K*POLW1_SIZE_PACKED]byte
	var outbuf [SHAKE256_RATE]byte

	copy(inbuf[:], mu[:])
	for i := 0; i < K; i++ {
		polyw1_pack(inbuf[CRHBYTES+i*POLW1_SIZE_PACKED:], &w1.vec[i])
	}

	state := sha3.NewShake256()
	state.Write(inbuf[:])
	state.Read(outbuf[:])

	signs := uint64(0)
	for i := uint(0); i < 8; i++ {
		signs |= uint64(outbuf[i]) << (8 * i)
	}

	mask := uint64(1)

	*c = poly{}
	pos := 0
	for i := 196; i < 256; i++ {
		var b int
		// randomly truncated hash outputs, huh?
		for {
			if pos >= SHAKE256_RATE {
				state.Read(outbuf[:])
				pos = 0
			}
			b = int(outbuf[pos])
			pos++
			if b <= i {
				break
			}
		}
		c.coeffs[i] = c.coeffs[b]

		// TODO FIXME vartime
		if (signs & mask) != 0 {
			c.coeffs[b] = Q - 1
		} else {
			c.coeffs[b] = 1
		}
		mask <<= 1
	}
}

// Take a random seed, and compute sk/pk pair.
func crypto_sign_keypair(seed []byte, pk *[PK_SIZE_PACKED]byte, sk *[SK_SIZE_PACKED]byte) []byte {
	var tr [CRHBYTES]byte
	var rho, rhoprime, key [SEEDBYTES]byte
	var s2, t, t1, t0 polyveck
	var s1, s1hat polyvecl
	var mat [K]polyvecl
	var nonce uint16

	if seed == nil {
		seed = make([]byte, SEEDBYTES)
		rand.Read(seed)
	}
	/* Expand 32 bytes of randomness into rho, rhoprime and key */
	state := sha3.NewShake256()
	state.Write(seed)
	state.Read(rho[:])
	state.Read(rhoprime[:])
	state.Read(key[:])

	/* Expand matrix */
	expand_mat(&mat, &rho)

	/* Sample short vectors s1 and s2 */
	for i := 0; i < L; i++ {
		if nonce > 255 {
			panic("bad mode")
		}
		poly_uniform_eta(&s1.vec[i], &rhoprime, byte(nonce))
		nonce++
	}
	for i := 0; i < K; i++ {
		if nonce > 255 {
			panic("bad mode")
		}
		poly_uniform_eta(&s2.vec[i], &rhoprime, byte(nonce))
		nonce++
	}

	/* Matrix-vector multiplication */
	s1hat = s1
	polyvecl_ntt(&s1hat)
	for i := 0; i < K; i++ {
		polyvecl_pointwise_acc_invmontgomery(&t.vec[i], &mat[i], &s1hat)
		poly_invntt_montgomery(&t.vec[i])
	}

	/* Add noise vector s2 */
	polyveck_add(&t, &t, &s2)

	/* Extract t1 and write public key */
	polyveck_freeze(&t)
	polyveck_power2round(&t1, &t0, &t)
	pack_pk(pk, &rho, &t1)

	/* Compute tr = CRH(rho, t1) and write secret key */
	sha3.ShakeSum256(tr[:], pk[:])
	pack_sk(sk, &rho, &key, &tr, &s1, &s2, &t0)

	return seed
}

func crypto_sign_detached(sm *[SIG_SIZE_PACKED]byte, m []byte, sk *[SK_SIZE_PACKED]byte) {
	var rho, key [SEEDBYTES]byte
	var tr, mu [CRHBYTES]byte
	var s1, y, yhat, z polyvecl
	var mat [K]polyvecl
	var s2, t0, w, w1, h, wcs2, wcs20, ct0, tmp polyveck
	var nonce uint16
	var c, chat poly

	unpack_sk(&rho, &key, &tr, &s1, &s2, &t0, sk)

	/* Compute CRH(tr, msg) */
	state := sha3.NewShake256()
	state.Write(tr[:])
	state.Write(m)
	state.Read(mu[:])

	/* Expand matrix and transform vectors */
	expand_mat(&mat, &rho)
	polyvecl_ntt(&s1)
	polyveck_ntt(&s2)
	polyveck_ntt(&t0)

rej:

	/* Sample intermediate vector y */
	for i := 0; i < L; i++ {
		poly_uniform_gamma1m1(&y.vec[i], &key, &mu, nonce)
		nonce++
	}

	/* Matrix-vector multiplication */
	yhat = y
	polyvecl_ntt(&yhat)
	for i := 0; i < K; i++ {
		polyvecl_pointwise_acc_invmontgomery(&w.vec[i], &mat[i], &yhat)
		poly_invntt_montgomery(&w.vec[i])
	}

	/* Decompose w and call the random oracle */
	polyveck_freeze(&w)
	polyveck_decompose(&w1, &tmp, &w)
	challenge(&c, &mu, &w1)

	/* Compute z, reject if it reveals secret */
	chat = c
	poly_ntt(&chat)
	for i := 0; i < L; i++ {
		poly_pointwise_invmontgomery(&z.vec[i], &chat, &s1.vec[i])
		poly_invntt_montgomery(&z.vec[i])
	}
	polyvecl_add(&z, &z, &y)
	polyvecl_freeze(&z)
	if polyvecl_chknorm(&z, GAMMA1-BETA) != 0 {
		goto rej
	}

	/* Compute w - cs2, reject if w1 can not be computed from it */
	for i := 0; i < K; i++ {
		poly_pointwise_invmontgomery(&wcs2.vec[i], &chat, &s2.vec[i])
		poly_invntt_montgomery(&wcs2.vec[i])
	}
	polyveck_sub(&wcs2, &w, &wcs2)
	polyveck_freeze(&wcs2)
	polyveck_decompose(&tmp, &wcs20, &wcs2)
	polyveck_freeze(&wcs20)
	if polyveck_chknorm(&wcs20, GAMMA2-BETA) != 0 {
		goto rej
	}

	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if tmp.vec[i].coeffs[j] != w1.vec[i].coeffs[j] {
				goto rej
			}
		}
	}

	/* Compute hints for w1 */
	for i := 0; i < K; i++ {
		poly_pointwise_invmontgomery(&ct0.vec[i], &chat, &t0.vec[i])
		poly_invntt_montgomery(&ct0.vec[i])
	}

	polyveck_freeze(&ct0)
	if polyveck_chknorm(&ct0, GAMMA2) != 0 {
		goto rej
	}

	polyveck_add(&tmp, &wcs2, &ct0)
	polyveck_neg(&ct0)
	polyveck_freeze(&tmp)
	n := polyveck_make_hint(&h, &tmp, &ct0)
	if n > OMEGA {
		goto rej
	}

	/* Write signature */
	pack_sig(sm, &z, &h, &c)
}

func crypto_verify_detached(sm *[SIG_SIZE_PACKED]byte, m []byte, pk *[PK_SIZE_PACKED]byte) bool {
	var rho [SEEDBYTES]byte
	var tr, mu [CRHBYTES]byte
	var c, chat, cp poly
	var z polyvecl
	var mat [K]polyvecl
	var t1, w1, h, tmp1, tmp2 polyveck

	if !unpack_sig(&z, &h, &c, sm) {
		return false
	}
	unpack_pk(&rho, &t1, pk)
	if polyvecl_chknorm(&z, GAMMA1-BETA) != 0 {
		return false
	}

	/* Compute mu = CRH(CRH(pk), msg) (pk = (rho, t1))  */
	sha3.ShakeSum256(tr[:], pk[:])
	state := sha3.NewShake256()
	state.Write(tr[:])
	state.Write(m)
	state.Read(mu[:])

	/* Expand rho matrix */
	expand_mat(&mat, &rho)

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	polyvecl_ntt(&z)
	for i := 0; i < K; i++ {
		polyvecl_pointwise_acc_invmontgomery(&tmp1.vec[i], &mat[i], &z)
	}

	chat = c
	poly_ntt(&chat)
	polyveck_shiftl(&t1, D)
	polyveck_ntt(&t1)
	for i := 0; i < K; i++ {
		poly_pointwise_invmontgomery(&tmp2.vec[i], &chat, &t1.vec[i])
	}

	polyveck_sub(&tmp1, &tmp1, &tmp2)
	polyveck_freeze(&tmp1) // reduce32 would be sufficient
	polyveck_invntt_montgomery(&tmp1)

	/* Reconstruct w1 */
	polyveck_freeze(&tmp1)
	polyveck_use_hint(&w1, &tmp1, &h)

	/* Call random oracle and verify challenge */
	challenge(&cp, &mu, &w1)
	for i := 0; i < N; i++ {
		if c.coeffs[i] != cp.coeffs[i] {
			return false
		}
	}

	return true
}

// attached sig wrappers
func crypto_sign(msg []byte, sk *[SK_SIZE_PACKED]byte) []byte {
	var sig [SIG_SIZE_PACKED]byte
	crypto_sign_detached(&sig, msg, sk)
	return append(sig[:], msg...)
}

func crypto_sign_open(msg []byte, pk *[PK_SIZE_PACKED]byte) []byte {
	var sig [SIG_SIZE_PACKED]byte
	if len(msg) < SIG_SIZE_PACKED {
		return nil
	}
	copy(sig[:], msg)
	d := msg[SIG_SIZE_PACKED:]
	if crypto_verify_detached(&sig, d, pk) {
		return d
	}
	return nil
}
