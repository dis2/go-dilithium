# Package dilithium
Implements experimental post-quantum digital signatures, presented in the paper
https://eprint.iacr.org/2017/633

This is a Go port of https://github.com/pq-crystals/dilithium

The algorithm is only a NIST submitted **phase 1 candidate** - and not standardized.
It's not recommended to use Dilithium in production, with the possible
exception of attaching it as accompanying signature to a classic scheme, such as
Ed25519.

## Porting notes

Most of the source code is ported 1:1 as close as possible - to the point of
completely violating Go's formatting standards. Don't run lint on this, it will
throw a pointless fit of nerd rage.

## Detached signatures

While the original code doesn't, this port implements detached signatures.
Detached signatures are variable sized (with upper bound) and live in a
separate buffer from the message.

## Performance comparison

In Go:
```
BenchmarkKeyPair           10000            157112 ns/op
BenchmarkSign               2000            816079 ns/op
BenchmarkVerify            10000            166918 ns/op
```

In plain C:
```
keygen:
median: 265750 ticks @ 2.3 GHz (0.1155 msecs, 115543.48ns/op)
average: 270348 ticks @ 2.3 GHz (0.1175 msecs, 117542.61ns/op)

sign:
median: 1273936 ticks @ 2.3 GHz (0.5539 msecs, 553885.22ns/op)
average: 1619273 ticks @ 2.3 GHz (0.704 msecs, 704031.74ns/op)

verify:
median: 283461 ticks @ 2.3 GHz (0.1232 msecs, 123243.91ns/op)
average: 288238 ticks @ 2.3 GHz (0.1253 msecs, 125320.87ns/op)
```

Which means the C version is roughly 15% faster.

## Implementation correctness and test data

Running `go test` will retrieve a large file (will be cached on disk) with the
official NIST submitted test vectors ("known good answers") and verify those
against this implementation.

