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

## Implementation correctness and test data

Running `go test` will retrieve a large file (will be cached on disk) with the
official NIST submitted test vectors ("known good answers") and verify those
against this implementation.

