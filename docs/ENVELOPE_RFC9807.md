# Envelope Operations - RFC 9807 Compliance

This document describes the envelope structure and operations as specified in RFC 9807 Section 5.1, and their implementation in the OPAQUE protocol.

## Overview

The envelope is a cryptographic container that protects client credentials during registration and authentication. It uses a combination of key derivation, encryption via XOR masking, and authentication via HMAC to ensure confidentiality and integrity.

## Envelope Structure (RFC 9807 Section 5.1)

According to RFC 9807, the envelope structure is:

```
struct {
  uint8 nonce[Nn];         // Envelope nonce (32 bytes)
  uint8 auth_tag[Nm];      // MAC authentication tag
} Envelope;
```

### Fields

- **nonce**: A random nonce of length `Nn` bytes (typically 32 bytes). This nonce is generated during envelope creation and is used to derive session-specific keys.
- **auth_tag**: A MAC authentication tag of length `Nm` bytes. This tag authenticates the envelope contents to prevent tampering.

## RFC 9807 Label Strings

The protocol uses specific label strings for key derivation as defined in RFC 9807:

| Label | Purpose | Usage |
|-------|---------|-------|
| `"MaskingKey"` | Credential masking | Used to XOR-mask the server public key in the credential response |
| `"AuthKey"` | Envelope authentication | Used to compute the HMAC authentication tag |
| `"ExportKey"` | Key export | Additional key material that can be exported for external use |
| `"PrivateKey"` | Client key derivation | Used to deterministically derive the client's private key |

These labels are defined in [common.ts](../src/common.ts#L36-L47):

```typescript
export const LABELS = {
    AuthKey: encStr('AuthKey'),
    MaskingKey: encStr('MaskingKey'),
    ExportKey: encStr('ExportKey'),
    PrivateKey: encStr('PrivateKey'),
    // ... other labels
} as const
```

## MAC Tag Coverage

The authentication tag provides integrity protection for the envelope and its associated cleartext credentials:

```typescript
auth_tag = MAC(auth_key, concat(nonce, cleartext_creds))
```

### Coverage Includes:
1. **Envelope nonce**: Ensures the nonce hasn't been tampered with
2. **Server public key**: Part of cleartext_creds, prevents key substitution attacks
3. **Server identity**: Part of cleartext_creds, binds the envelope to a specific server
4. **Client identity**: Part of cleartext_creds, binds the envelope to a specific client

This comprehensive coverage ensures that any modification to the envelope or credentials will be detected during recovery.

## Store Operation

The `Store` operation creates an envelope during client registration.

### Algorithm

```
Store(randomized_pwd, server_public_key, server_identity, client_identity):

  1. envelope_nonce = random(Nn)
  
  2. Derive keys using HKDF-Expand:
     masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
     auth_key = Expand(randomized_pwd, concat(nonce, "AuthKey"), Nh)
     export_key = Expand(randomized_pwd, concat(nonce, "ExportKey"), Nh)
     seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nseed)
  
  3. client_private_key, client_public_key = DeriveKeyPair(seed)
  
  4. cleartext_creds = {server_public_key, server_identity, client_identity}
  
  5. auth_tag = MAC(auth_key, concat(nonce, cleartext_creds))
  
  6. envelope = {nonce: envelope_nonce, auth_tag}
  
  7. Return (envelope, client_public_key, masking_key, export_key)
```

### Side Effects
- **Crypto RNG**: Generates random nonce (1 side effect)
- **Logging**: Debug logging (1 side effect)
- **Total**: 2 side effects ✓

## Recover Operation

The `Recover` operation extracts credentials from an envelope during client authentication.

### Algorithm

```
Recover(randomized_pwd, envelope, server_public_key, server_identity, client_identity):

  1. Re-derive keys using the same process as Store:
     auth_key = Expand(randomized_pwd, concat(envelope.nonce, "AuthKey"), Nh)
     export_key = Expand(randomized_pwd, concat(envelope.nonce, "ExportKey"), Nh)
     seed = Expand(randomized_pwd, concat(envelope.nonce, "PrivateKey"), Nseed)
  
  2. client_private_key = DeriveKeyPair(seed).private
  
  3. cleartext_creds = {server_public_key, server_identity, client_identity}
  
  4. expected_tag = MAC(auth_key, concat(envelope.nonce, cleartext_creds))
  
  5. If expected_tag ≠ envelope.auth_tag:
       Return Error("Envelope authentication failed")
  
  6. Return (client_private_key, export_key)
```

### Side Effects
- **Logging**: Debug logging (1 side effect)
- **Total**: 1 side effect ✓

## Functional API

The envelope operations are implemented using functional programming principles with Either monads for error handling.

### Creating Envelope Operations

```typescript
import { createEnvelopeOps } from './envelope-functional.js'
import { OpaqueConfig, OpaqueID } from './suites.js'

const config = new OpaqueConfig(OpaqueID.OPAQUE_P256)
const ops = createEnvelopeOps(config)
```

### Store Example

```typescript
import { createCleartextCredentials } from './envelope-functional.js'

// Prepare inputs
const randomized_pwd = new Uint8Array(32) // From OPRF output
const server_public_key = new Uint8Array(33) // Server's public key
const server_identity = new TextEncoder().encode('server.example.com')
const client_identity = new TextEncoder().encode('user@example.com')

const creds = createCleartextCredentials(
  server_public_key
)(server_identity)(client_identity)

// Mock key derivation (in practice, use AKE.DeriveKeyPair)
const deriveKeyPair = async (seed: Uint8Array) => {
  // ... derive key pair from seed
  return Right({ private: privateKey, public: publicKey })
}

// Store envelope
const result = await ops.store(randomized_pwd, creds, deriveKeyPair)

if (result.isRight()) {
  const { envelope, client_public_key, masking_key, export_key } = result.unsafeCoerce()
  // envelope can now be stored in the registration record
} else {
  const error = result.unsafeCoerce()
  console.error('Store failed:', error.message)
}
```

### Recover Example

```typescript
// During authentication, recover credentials from envelope
const result = await ops.recover(randomized_pwd, envelope, creds, deriveKeyPair)

if (result.isRight()) {
  const { client_private_key, export_key } = result.unsafeCoerce()
  // Use client_private_key for authentication
} else {
  const error = result.unsafeCoerce()
  console.error('Recovery failed:', error.message)
  // Authentication should fail - invalid password or tampered envelope
}
```

## Security Properties

### Confidentiality
- Client private key is never stored directly
- Derived deterministically from `randomized_pwd` and `nonce`
- Requires knowledge of the password to recover

### Integrity
- HMAC authentication tag protects envelope and credentials
- Any modification to nonce, credentials, or password will cause verification failure
- Prevents server from substituting different credentials

### Binding
- Envelope is cryptographically bound to:
  - Client's password (via `randomized_pwd`)
  - Server's public key
  - Server and client identities
- Prevents credential reuse attacks

## Implementation Notes

### Currying
All envelope operations are fully curried, allowing partial application:

```typescript
// Bind configuration
const storeWithConfig = storeEnvelope(config)

// Bind password
const storeWithPassword = storeWithConfig(randomized_pwd)

// Apply remaining parameters
const result = await storeWithPassword(creds)(deriveKeyPair)
```

### Either Monads
Operations return `Either<Error, Result>` instead of throwing exceptions:
- `Right(result)`: Operation succeeded
- `Left(error)`: Operation failed

This makes error handling explicit and composable.

### Type Safety
TypeScript types ensure:
- Correct parameter order
- Proper Either handling
- No null/undefined issues
- Immutable data structures

## Testing

See [envelope-rfc9807.test.ts](../test/envelope-rfc9807.test.ts) for comprehensive test coverage including:
- Store/recover round-trip
- Authentication failure detection
- Modified envelope detection
- Multiple cipher suite support
- RFC 9807 label verification

## References

- [RFC 9807: The OPAQUE Asymmetric PAKE Protocol](https://www.rfc-editor.org/rfc/rfc9807.html)
- [RFC 9807 Section 5.1: Envelope Structure](https://www.rfc-editor.org/rfc/rfc9807.html#section-5.1)
- [Implementation: envelope-functional.ts](../src/envelope-functional.ts)
