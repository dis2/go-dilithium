package dilithium

type polyveck struct {
	vec [K]poly
}

type polyvecl struct {
	vec [L]poly
}

func polyvecl_freeze(v *polyvecl) {
	for i := 0; i < L; i++ {
		poly_freeze(&v.vec[i])
	}
}

func polyvecl_add(w, u, v *polyvecl) {
	for i := 0; i < L; i++ {
		poly_add(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}

func polyvecl_ntt(v *polyvecl) {
	for i := 0; i < L; i++ {
		poly_ntt(&v.vec[i])
	}
}

func polyvecl_pointwise_acc_invmontgomery(w *poly, u, v *polyvecl) {
	var t poly

	poly_pointwise_invmontgomery(w, &u.vec[0], &v.vec[0])

	for i := 1; i < L; i++ {
		poly_pointwise_invmontgomery(&t, &u.vec[i], &v.vec[i])
		poly_add(w, w, &t)
	}

	for i := 0; i < N; i++ {
		w.coeffs[i] = reduce32(w.coeffs[i])
	}
}

func polyvecl_chknorm(v *polyvecl, bound uint32) (ret int) {
	for i := 0; i < L; i++ {
		ret |= poly_chknorm(&v.vec[i], bound)
	}

	return ret
}

func polyveck_freeze(v *polyveck) {
	for i := 0; i < K; i++ {
		poly_freeze(&v.vec[i])
	}
}

func polyveck_add(w, u, v *polyveck) {
	for i := 0; i < K; i++ {
		poly_add(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}
func polyveck_sub(w, u, v *polyveck) {
	for i := 0; i < K; i++ {
		poly_sub(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}

func polyveck_neg(v *polyveck) {
	for i := 0; i < K; i++ {
		poly_neg(&v.vec[i])
	}
}

func polyveck_shiftl(v *polyveck, k uint) {
	for i := 0; i < K; i++ {
		poly_shiftl(&v.vec[i], k)
	}
}

func polyveck_ntt(v *polyveck) {
	for i := 0; i < K; i++ {
		poly_ntt(&v.vec[i])
	}
}
func polyveck_invntt_montgomery(v *polyveck) {
	for i := 0; i < K; i++ {
		poly_invntt_montgomery(&v.vec[i])
	}
}

func polyveck_chknorm(v *polyveck, bound uint32) (ret int) {
	for i := 0; i < K; i++ {
		ret |= poly_chknorm(&v.vec[i], bound)
	}
	return ret
}

func polyveck_power2round(v1, v0, v *polyveck) {
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			v1.vec[i].coeffs[j] = power2round(v.vec[i].coeffs[j],
				&v0.vec[i].coeffs[j])

		}
	}
}

func polyveck_decompose(v1, v0, v *polyveck) {
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			v1.vec[i].coeffs[j] = decompose(v.vec[i].coeffs[j],
				&v0.vec[i].coeffs[j])
		}
	}
}

func polyveck_make_hint(h, u, v *polyveck) (s uint32) {
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			h.vec[i].coeffs[j] = make_hint(u.vec[i].coeffs[j], v.vec[i].coeffs[j])
			s += h.vec[i].coeffs[j]
		}
	}
	return s
}

func polyveck_use_hint(w, u, h *polyveck) {
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			w.vec[i].coeffs[j] = use_hint(u.vec[i].coeffs[j], h.vec[i].coeffs[j])
		}
	}
}
