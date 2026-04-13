# RFC 9807 Test Vectors Documentation

## Overview

This document describes the RFC 9807 test vector validation implemented in this project. The test vectors are extracted from RFC 9807 Appendix C and validate 100% compliance with the official OPAQUE specification.

## Test Vector Sources

### RFC 9807 Appendix C

All test vectors are sourced from [RFC 9807](https://datatracker.ietf.org/doc/html/rfc9807) Appendix C:

- **Section C.1**: Real Test Vectors (legitimate user authentication)
- **Section C.2**: Fake Test Vectors (enumeration prevention)

The test vectors are static and standardized as part of the RFC specification.

## Test Vector Files

### Location

All test vectors are stored in: `test/vectors-rfc9807/`

### Files

1. **`ristretto255-sha512-real-vector-1.json`**
   - Configuration: ristretto255-SHA512
   - Source: RFC 9807 Appendix C.1.1
   - Identities: None (uses public keys as identities)
   - Tests: Registration and authentication flow

2. **`ristretto255-sha512-real-vector-2.json`**
   - Configuration: ristretto255-SHA512  
   - Source: RFC 9807 Appendix C.1.2
   - Identities: client_identity="alice", server_identity="bob"
   - Tests: Registration and authentication with explicit identities

3. **`p256-sha256-real-vector-5.json`**
   - Configuration: P256-SHA256
   - Source: RFC 9807 Appendix C.1.5
   - Identities: None
   - Tests: P256 curve support

4. **`ristretto255-sha512-fake-vector-1.json`**
   - Configuration: ristretto255-SHA512
   - Source: RFC 9807 Appendix C.2.1
   - Purpose: Fake credential response for enumeration prevention

### JSON Structure

Each test vector file contains:

```json
{
  "comment": "Description and RFC section reference",
  "config": {
    "OPRF": "ristretto255-SHA512",
    "Hash": "SHA512",
    "KSF": "Identity",
    "KDF": "HKDF-SHA512",
    "MAC": "HMAC-SHA512",
    "Group": "ristretto255",
    "Context": "4f50415155452d504f43",
    "Nh": 64,
    "Npk": 32,
    "Nsk": 32,
    "Nm": 64,
    "Nx": 64,
    "Nok": 32
  },
  "inputs": {
    "oprf_seed": "...",
    "credential_identifier": "...",
    "password": "...",
    ...
  },
  "intermediates": {
    "client_public_key": "...",
    "auth_key": "...",
    "randomized_password": "...",
    ...
  },
  "outputs": {
    "registration_request": "...",
    "registration_response": "...",
    "registration_upload": "...",
    "KE1": "...",
    "KE2": "...",
    "KE3": "...",
    "export_key": "...",
    "session_key": "..."
  }
}
```

All hex values are lowercase without separators.

## Test Suites

### Registration Vectors

**File**: `test/rfc9807-registration-vectors.test.ts`

Tests registration flow compliance:
- OPRF request/response structure
- Envelope creation and storage
- Registration record format
- Message size validation
- Intermediate value verification

**Run**: `npm run test:vectors:registration`

### Authentication Vectors

**File**: `test/rfc9807-authentication-vectors.test.ts`

Tests authentication flow compliance:
- KE1, KE2, KE3 message structures
- Credential retrieval
- Session key derivation
- Export key derivation
- Intermediate value validation (handshake secret, MAC keys)

**Run**: `npm run test:vectors:authentication`

### Fake Response Vectors

**File**: `test/rfc9807-fake-response-vectors.test.ts`

Tests fake credential response for enumeration prevention:
- KE2 structure matches real response
- Indistinguishability from real authentication
- Proper use of fake record parameters
- Security properties (nonces, MACs)

**Run**: `npm run test:vectors:fake`

### All Vector Tests

**Run**: `npm run test:vectors`

Runs all RFC 9807 test vector suites.

## Validation Utilities

### Hex Conversion

```typescript
import { hexToBytes, bytesToHex } from '../src/test-utils/vector-validation.js'

const bytes = hexToBytes('48656c6c6f')  // "Hello"
const hex = bytesToHex(new Uint8Array([72, 101, 108, 108, 111]))  // "48656c6c6f"
```

### Byte Comparison

```typescript
import { bytesEqual, assertBytesEqual } from '../src/test-utils/vector-validation.js'

const equal = bytesEqual(actual, expected)  // boolean

assertBytesEqual(actual, expected, 'Client public key')
  .mapLeft(err => { throw err })  // Either monad pattern
```

### Loading Test Vectors

```typescript
import { loadTestVector } from '../src/test-utils/vector-validation.js'

const vector = await loadTestVector('ristretto255-sha512-real-vector-1.json')
```

### Parsing Hex Fields

```typescript
import { parseVectorHex } from '../src/test-utils/vector-validation.js'

const inputs = parseVectorHex(vector.inputs)
// Converts all hex string fields to Uint8Array
```

## RFC 9807 Compliance Checklist

### Configuration Support

- [x] ristretto255-SHA512
- [x] P256-SHA256
- [x] HKDF-SHA512 / HKDF-SHA256
- [x] HMAC-SHA512 / HMAC-SHA256
- [x] Identity KSF (test vectors use no key stretching)

### Registration Flow (Section 5)

- [x] CreateRegistrationRequest message format
- [x] CreateRegistrationResponse message format
- [x] RegistrationRecord structure
- [x] OPRF blinding and evaluation
- [x] Envelope creation with auth_key and export_key
- [x] Masking key derivation

### Authentication Flow (Section 6)

- [x] KE1 message structure (CredentialRequest + AuthRequest)
- [x] KE2 message structure (CredentialResponse + AuthResponse)
- [x] KE3 message structure (client MAC)
- [x] Credential retrieval and envelope recovery
- [x] Session key derivation
- [x] Export key availability

### 3DH Key Exchange (Section 6.4)

- [x] Preamble construction
- [x] Triple Diffie-Hellman computation
- [x] Handshake secret derivation
- [x] Server MAC and Client MAC derivation
- [x] Transcript hashing

### Envelope (Section 4.1)

- [x] Envelope structure (nonce + auth_tag)
- [x] Envelope creation (Store function)
- [x] Envelope recovery (Recover function)
- [x] Auth key derivation with envelope nonce
- [x] Export key derivation with envelope nonce

### Security Features

- [x] Fake credential response indistinguishability
- [x] Masking key for credential response protection
- [x] Client enumeration prevention
- [x] Proper nonce handling (client, server, envelope, masking)

### Intermediate Values

- [x] OPRF key derivation from seed
- [x] Randomized password computation
- [x] Handshake secret derivation
- [x] MAC key derivation (server and client)
- [x] Auth key verification

### Message Sizes

- [x] All message sizes match RFC 9807 specifications
- [x] ristretto255: Noe=32, Npk=32, Nh=64, Nm=64
- [x] P256: Noe=33, Npk=33, Nh=32, Nm=32

## Implementation Notes

### Test Vector Determinism

The test vectors use fixed random values (seeds, nonces, blinds) to ensure deterministic output. In production:

- Use cryptographically secure random generation
- Never reuse nonces
- Generate fresh blinds for each OPRF operation

### Identity Handling

Test vectors demonstrate two identity modes:

1. **Default**: Identities default to public keys (Vector 1, 5)
2. **Explicit**: Application-specific identities (Vector 2)

Both modes are RFC 9807 compliant.

### KSF Configuration

Test vectors use the Identity KSF (no key stretching). Production deployments SHOULD use:

- Argon2id with appropriate parameters
- scrypt as an alternative
- See RFC 9807 Section 7 for recommended configurations

## Continuous Integration

### GitHub Actions

The test vector suite runs automatically in CI/CD:

```yaml
- name: Run RFC 9807 Test Vectors
  run: npm run test:vectors
```

### Pre-commit Hooks

Recommended: Add vector validation to pre-commit:

```bash
npm run test:vectors
```

## Adding New Test Vectors

To add additional test vectors from RFC 9807 or other sources:

1. Create JSON file in `test/vectors-rfc9807/`
2. Follow existing structure
3. Add test cases in appropriate test suite
4. Verify all hex values are lowercase and correctly formatted
5. Run `npm run test:vectors` to validate

## Troubleshooting

### Hex Parsing Errors

```
Error: Invalid hex string length
```

**Solution**: Ensure all hex strings have even length and contain only 0-9, a-f characters.

### Length Mismatches

```
Expected length X, got Y
```

**Solution**: Verify message structure matches RFC 9807 specification for the configuration.

### Byte Comparison Failures

```
Client public key mismatch:
  Expected: 76a845...
  Actual:   84f43f...
```

**Solution**: Check implementation against RFC 9807 specification. Verify all inputs and intermediate computations.

## References

- [RFC 9807: The OPAQUE aPAKE Protocol](https://datatracker.ietf.org/doc/html/rfc9807)
- [RFC 9497: OPRFs Using Prime-Order Groups](https://datatracker.ietf.org/doc/html/rfc9497)
- [RFC 5869: HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 2104: HMAC](https://datatracker.ietf.org/doc/html/rfc2104)

## Contact

For questions about RFC 9807 compliance or test vector validation, consult the RFC or IETF CFRG mailing list.
