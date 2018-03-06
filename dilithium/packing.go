package dilithium

func pack_pk(pkb *[PK_SIZE_PACKED]byte, rho *[SEEDBYTES]byte, t1 *polyveck) {
	pk := pkb[:]
	copy(pk[:], rho[:])
	pk = pk[SEEDBYTES:]
	for i := 0; i < K; i++ {
		polyt1_pack(pk[i*POLT1_SIZE_PACKED:], &t1.vec[i])
	}
}

func unpack_pk(rho *[SEEDBYTES]byte,
	t1 *polyveck,
	pkb *[PK_SIZE_PACKED]byte) {
	pk := pkb[:]
	copy(rho[:], pk[:])
	pk = pk[SEEDBYTES:]
	for i := 0; i < K; i++ {
		polyt1_unpack(&t1.vec[i], pk[i*POLT1_SIZE_PACKED:])
	}
}

func pack_sk(skb *[SK_SIZE_PACKED]byte,
	rho, key *[SEEDBYTES]byte,
	tr *[CRHBYTES]byte,
	s1 *polyvecl,
	s2, t0 *polyveck) {
	sk := skb[:]
	copy(sk[:], rho[:])

	copy(sk[SEEDBYTES:], key[:])
	copy(sk[SEEDBYTES*2:], tr[:])

	sk = sk[SEEDBYTES*2+CRHBYTES:]

	for i := 0; i < L; i++ {
		polyeta_pack(sk[i*POLETA_SIZE_PACKED:], &s1.vec[i])
	}
	sk = sk[L*POLETA_SIZE_PACKED:]

	for i := 0; i < K; i++ {
		polyeta_pack(sk[i*POLETA_SIZE_PACKED:], &s2.vec[i])
	}
	sk = sk[K*POLETA_SIZE_PACKED:]

	for i := 0; i < K; i++ {
		polyt0_pack(sk[i*POLT0_SIZE_PACKED:], &t0.vec[i])
	}
}

func unpack_sk(rho *[SEEDBYTES]byte,
	key *[SEEDBYTES]byte,
	tr *[CRHBYTES]byte,
	s1 *polyvecl,
	s2, t0 *polyveck,
	skb *[SK_SIZE_PACKED]byte) {
	sk := skb[:]
	copy(rho[:], sk[:])
	copy(key[:], sk[SEEDBYTES:])
	copy(tr[:], sk[SEEDBYTES*2:])
	sk = sk[SEEDBYTES*2+CRHBYTES:]

	for i := 0; i < L; i++ {
		polyeta_unpack(&s1.vec[i], sk[i*POLETA_SIZE_PACKED:])
	}
	sk = sk[L*POLETA_SIZE_PACKED:]

	for i := 0; i < K; i++ {
		polyeta_unpack(&s2.vec[i], sk[i*POLETA_SIZE_PACKED:])
	}
	sk = sk[K*POLETA_SIZE_PACKED:]

	for i := 0; i < K; i++ {
		polyt0_unpack(&t0.vec[i], sk[i*POLT0_SIZE_PACKED:])
	}
}

func pack_sig(sigb *[SIG_SIZE_PACKED]byte, z *polyvecl, h *polyveck, c *poly) {
	sig := sigb[:]

	for i := 0; i < L; i++ {
		polyz_pack(sigb[i*POLZ_SIZE_PACKED:], &z.vec[i])
	}
	sig = sig[L*POLZ_SIZE_PACKED:]

	/* Encode h */
	k := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if h.vec[i].coeffs[j] == 1 {
				sig[k] = byte(j)
				k++
			}
			sig[OMEGA+i] = byte(k)
		}
	}
	for k < OMEGA {
		sig[k] = 0
		k++
	}
	sig = sig[OMEGA+K:]

	/* Encode c */
	signs := uint64(0)
	mask := uint64(1)
	for i := uint(0); i < N/8; i++ {
		sig[i] = 0
		for j := uint(0); j < 8; j++ {
			if c.coeffs[8*i+j] != 0 {
				sig[i] |= byte(1 << j)
				if c.coeffs[8*i+j] == (Q - 1) {
					signs |= mask
				}
				mask <<= 1
			}
		}
	}
	sig = sig[N/8:]
	for i := uint(0); i < 8; i++ {
		sig[i] = byte(signs >> (8 * i))
	}
}


func unpack_sig(z *polyvecl,
	h *polyveck,
	c *poly,
	sigb *[SIG_SIZE_PACKED]byte) bool {

	sig := sigb[:]
	for i := 0; i < L; i++ {
		polyz_unpack(&z.vec[i], sigb[i*POLZ_SIZE_PACKED:])
	}
	sig = sig[L*POLZ_SIZE_PACKED:]
	rem := len(sig)

	/* Decode h */
	k := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			h.vec[i].coeffs[j] = 0
		}
		limit := int(sig[OMEGA+i])
		if limit > rem {
			return false
		}
		for j := k; j < limit; j++ {
			h.vec[i].coeffs[sig[j]] = 1
		}
		k = int(sig[OMEGA+i])
	}
	sig = sig[OMEGA+K:]

	/* Decode c */
	*c = poly{}

	signs := uint64(0)
	for i := uint(0); i < 8; i++ {
		signs |= uint64(sig[N/8+i]) << (8 * i)
	}

	mask := uint64(1)
	for i := uint(0); i < N/8; i++ {
		for j := uint(0); j < 8; j++ {
			if ((sig[i] >> j) & 0x01) != 0 {
				if (signs & mask) != 0 {
					c.coeffs[8*i+j] = Q - 1
				} else {
					c.coeffs[8*i+j] = 1
				}

				mask <<= 1
			}
		}
	}
	return true
}

func pack_sig_detached(sigb *[SIG_SIZE_PACKED]byte, z *polyvecl, h *polyveck, c *poly) []byte {
	sig := sigb[:]

	for i := 0; i < L; i++ {
		polyz_pack(sigb[i*POLZ_SIZE_PACKED:], &z.vec[i])
	}
	sig = sig[L*POLZ_SIZE_PACKED:]

	/* Encode h */
	k := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if h.vec[i].coeffs[j] == 1 {
				sig[K+k] = byte(j)
				k++
			}
			sig[i] = byte(k)
		}
	}
	sig = sig[K+k:]

	/* Encode c */
	signs := uint64(0)
	mask := uint64(1)
	for i := uint(0); i < N/8; i++ {
		sig[i] = 0
		for j := uint(0); j < 8; j++ {
			if c.coeffs[8*i+j] != 0 {
				sig[i] |= byte(1 << j)
				if c.coeffs[8*i+j] == (Q - 1) {
					signs |= mask
				}
				mask <<= 1
			}
		}
	}
	sig = sig[N/8:]
	for i := uint(0); i < 8; i++ {
		sig[i] = byte(signs >> (8 * i))
	}
	sig = sig[8:]

	return sigb[0:SIG_SIZE_PACKED-len(sig)]
}


func unpack_sig_detached(z *polyvecl,
	h *polyveck,
	c *poly,
	sig []byte) bool {

	for i := 0; i < L; i++ {
		polyz_unpack(&z.vec[i], sig[i*POLZ_SIZE_PACKED:])
	}
	sig = sig[L*POLZ_SIZE_PACKED:]
	rem := len(sig)

	/* Decode h */
	k := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			h.vec[i].coeffs[j] = 0
		}
		limit := int(sig[i])
		if limit > rem {
			return false
		}
		for j := k; j < limit; j++ {
			h.vec[i].coeffs[sig[K+j]] = 1
		}
		k = int(sig[i])
	}
	if len(sig) - (K+k) < (N/8 + 8) {
		return false
	}
	sig = sig[K+k:]

	/* Decode c */
	*c = poly{}

	signs := uint64(0)
	for i := uint(0); i < 8; i++ {
		signs |= uint64(sig[N/8+i]) << (8 * i)
	}

	mask := uint64(1)
	for i := uint(0); i < N/8; i++ {
		for j := uint(0); j < 8; j++ {
			if ((sig[i] >> j) & 0x01) != 0 {
				if (signs & mask) != 0 {
					c.coeffs[8*i+j] = Q - 1
				} else {
					c.coeffs[8*i+j] = 1
				}

				mask <<= 1
			}
		}
	}
	return true
}
