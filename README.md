# opaque-ts-rfc9807

An enhanced Typescript implementation of the OPAQUE (Asymmetric Password-Authenticated Key Exchange) protocol with full compliance to [RFC 9807](https://datatracker.ietf.org/doc/html/rfc9807).

## Features

This implementation provides:

- **RFC 9807 Compliance** — Complete implementation aligned with the final RFC 9807 specification
- Functional implementations of cryptographic primitives with detailed documentation
- Comprehensive test vectors and compliance validation
- RFC 9497 (OPRF) compliance verification
- Detailed protocol documentation for all components:
  - 3DH (Three-Diffie-Hellman handshake)
  - OPRF (Oblivious Pseudorandom Function)
  - Envelope operations
  - Authentication flows
  - Registration flows

## Specification

- [RFC 9807 — OPAQUE](https://datatracker.ietf.org/doc/html/rfc9807)
- [RFC 9497 — Oblivious Pseudorandom Functions (OPRFs)](https://datatracker.ietf.org/doc/html/rfc9497)

## Test and Coverage

```sh
npm ci
npm test
```

## Dependencies

Uses `@cloudflare/voprf-ts` for the group and OPRF operations, WebCrypto API for hashing and key derivation functions, and `@noble/hashes` for scrypt memory-hard function.

## Attribution

This implementation is based on [Cloudflare's opaque-ts](https://github.com/cloudflare/opaque-ts), originally developed by Armando Faz and contributors at Cloudflare.

## License

[BSD-3-Clause](LICENSE.txt)
