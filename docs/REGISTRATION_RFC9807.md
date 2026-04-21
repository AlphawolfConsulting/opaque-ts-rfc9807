# Registration Flow - RFC 9807 Compliance

**Document Version**: 1.0  
**RFC Reference**: RFC 9807 Section 5  
**Last Updated**: February 6, 2026

---

## Overview

This document describes the OPAQUE registration flow as implemented in `registration-functional.ts`, which strictly follows RFC 9807 Section 5 specifications. The registration process allows a client to establish credentials with a server without revealing the password to the server.

The implementation uses:

- **Either monads** for error handling
- **Currying** for function composition
- **Proper side effect management** (≤2 per function)
- **RFC 9807 compliant message structures**

---

## Registration Protocol

### Three-Step Process

```text
CLIENT                                              SERVER
------                                              ------

password
   |
   v
[CreateRegistrationRequest]
   |
   +----(RegistrationRequest)------>
                                                      |
                                                      v
                                          [CreateRegistrationResponse]
                                                      |
   <----(RegistrationResponse)------------+
   |
   v
[FinalizeRequest]
   |
   +----(RegistrationRecord)------->
                                                      |
                                                      v
                                          [Store record for user]
```

### Step 1: Create Registration Request (Client)

**Function**: `createRegistrationRequest`

The client blinds the password using OPRF (Oblivious Pseudorandom Function) to create a registration request.

**Input**:

- `password: Uint8Array` - User's password

**Output**: `Either<Error, RegistrationRequestResult>`

```typescript
interface RegistrationRequestResult {
  request: {
    data: Uint8Array  // Blinded element (OPRF)
  }
  blind: Uint8Array   // Blind value (kept secret by client)
  requestId: string   // Tracking ID (not cryptographic)
}
```

**RFC 9807 Message Structure**:

```c
struct {
  uint8 data[Noe];  // Blinded password element
} RegistrationRequest;
```

**Example**:

```typescript
import { createRegistrationOps } from './registration-functional.js'
import { OpaqueConfig, OpaqueID } from './suites.js'

const config = new OpaqueConfig(OpaqueID.OPAQUE_P256)
const ops = createRegistrationOps(config)

const password = new TextEncoder().encode('correct horse battery staple')

const requestResult = await ops.createRequest(password)

if (requestResult.isRight()) {
  const { request, blind, requestId } = requestResult.unsafeCoerce()
  console.log('Request ID:', requestId)
  console.log('Blinded element size:', request.data.length)
  // Send request.data to server
  // Keep blind secret for finalization
} else {
  console.error('Request creation failed:', requestResult.extract())
}
```

**Side Effects**:

- Crypto RNG (OPRF blinding)
- Logging

---

### Step 2: Create Registration Response (Server)

**Function**: `createRegistrationResponse`

The server evaluates the blinded element using its OPRF seed and returns the evaluation along with its public key.

**Input**:

- `request: { data: Uint8Array }` - Registration request from client
- `server_public_key: Uint8Array` - Server's AKE public key
- `oprf_seed: Uint8Array` - Server's OPRF seed (kept secret)

**Output**: `Either<Error, RegistrationResponse>`

```typescript
interface RegistrationResponse {
  data: Uint8Array             // OPRF evaluation
  server_public_key: Uint8Array // Server's AKE public key
}
```

**RFC 9807 Message Structure**:

```c
struct {
  uint8 data[Noe];                  // OPRF evaluation
  uint8 server_public_key[Npk];    // Server AKE public key
} RegistrationResponse;
```

**Example**:

```typescript
// Server receives request from client
const server_public_key = new Uint8Array(33) // P256 public key
const oprf_seed = new Uint8Array(32)         // Secret OPRF seed

const responseResult = await ops.createResponse(
  request,
  server_public_key,
  oprf_seed
)

if (responseResult.isRight()) {
  const response = responseResult.unsafeCoerce()
  console.log('Evaluation size:', response.data.length)
  console.log('Server public key size:', response.server_public_key.length)
  // Send response back to client
} else {
  console.error('Response creation failed:', responseResult.extract())
}
```

**Side Effects**:

- Logging

**Key Derivation**:
The server derives the OPRF key from its seed using:

```ts
oprf_key_seed = HKDF-Expand(oprf_seed, "OprfKey", Nseed)
oprf_key = DeriveKeyPair(oprf_key_seed)
```

---

### Step 3: Finalize Registration (Client)

**Function**: `finalizeRegistrationRequest`

The client finalizes the OPRF output, derives a randomized password, creates an envelope with credentials, and generates the registration record.

**Input**:

- `password: Uint8Array` - Original password
- `blind: Uint8Array` - Blind value from step 1
- `response: RegistrationResponse` - Response from server
- `server_identity: Uint8Array` - Server identity (e.g., domain name)
- `client_identity: Uint8Array` - Client identity (e.g., username)
- `ksf: KSFFn` - Key stretching function (IdentityKSF or ScryptKSF)
- `deriveKeyPair: Function` - AKE key pair derivation function

**Output**: `Either<Error, RegistrationFinalizeResult>`

```typescript
interface RegistrationFinalizeResult {
  record: RegistrationRecord  // To be stored by server
  export_key: Uint8Array      // Client's export key
  recordId: string            // Tracking ID (not cryptographic)
}

interface RegistrationRecord {
  client_public_key: Uint8Array
  masking_key: Uint8Array
  envelope: {
    nonce: Uint8Array
    auth_tag: Uint8Array
  }
}
```

**RFC 9807 Message Structure**:

```c
struct {
  uint8 client_public_key[Npk];  // Client AKE public key
  uint8 masking_key[Nh];          // For credential masking
  Envelope envelope;               // Encrypted credentials
} RegistrationRecord;

struct {
  uint8 nonce[Nn];        // Random nonce
  uint8 auth_tag[Nm];     // MAC authentication tag
} Envelope;
```

**Example**:

```typescript
import { IdentityKSFFn } from './thecrypto.js'

const server_identity = new TextEncoder().encode('server.example')
const client_identity = new TextEncoder().encode('alice@example.com')

// Define key pair derivation (example using config's AKE)
const deriveKeyPair = async (seed: Uint8Array) => {
  try {
    const keypair = await config.ake.deriveDHKeyPair(seed)
    return Right({
      private: keypair.private_key,
      public: keypair.public_key
    })
  } catch (e) {
    return Left(e as Error)
  }
}

const finalizeResult = await ops.finalizeRequest(
  password,
  blind,
  response,
  server_identity,
  client_identity,
  IdentityKSFFn,
  deriveKeyPair
)

if (finalizeResult.isRight()) {
  const { record, export_key, recordId } = finalizeResult.unsafeCoerce()
  console.log('Record ID:', recordId)
  console.log('Client public key size:', record.client_public_key.length)
  console.log('Masking key size:', record.masking_key.length)
  console.log('Envelope nonce size:', record.envelope.nonce.length)
  console.log('Envelope auth tag size:', record.envelope.auth_tag.length)
  console.log('Export key size:', export_key.length)
  // Send record to server for storage
  // Keep export_key for application use
} else {
  console.error('Finalization failed:', finalizeResult.extract())
}
```

**Side Effects**:

- Crypto RNG (envelope nonce generation)
- Logging

**Randomized Password Derivation** (RFC 9807 Section 3.3):

```ts
oprf_output = OPRF.Finalize(password, blind, evaluation)
stretched = HKDF-Extract("", oprf_output)
randomized_pwd = KSF(stretched)  // Or stretched if KSF is Identity
```

**Envelope Creation** (RFC 9807 Section 5.1):

```ts
nonce = random(Nn)
auth_key = HKDF-Expand(randomized_pwd, nonce || "AuthKey", Nh)
export_key = HKDF-Expand(randomized_pwd, nonce || "ExportKey", Nh)
seed = HKDF-Expand(randomized_pwd, nonce || "PrivateKey", Nseed)
client_keypair = DeriveKeyPair(seed)
masking_key = HKDF-Expand(randomized_pwd, "MaskingKey", Nh)

cleartext_creds = {
  server_public_key,
  server_identity,
  client_identity
}

auth_tag = MAC(auth_key, nonce || cleartext_creds)

envelope = { nonce, auth_tag }
```

---

## Complete Registration Example

```typescript
import { createRegistrationOps } from './registration-functional.js'
import { OpaqueConfig, OpaqueID } from './suites.js'
import { IdentityKSFFn } from './thecrypto.js'
import { Right, Left } from 'purify-ts'

async function registerUser() {
  const config = new OpaqueConfig(OpaqueID.OPAQUE_P256)
  const ops = createRegistrationOps(config)
  
  // User inputs
  const password = new TextEncoder().encode('my secure password')
  const username = 'alice@example.com'
  const serverDomain = 'server.example'
  
  // CLIENT: Step 1 - Create registration request
  console.log('CLIENT: Creating registration request...')
  const requestResult = await ops.createRequest(password)
  
  if (requestResult.isLeft()) {
    throw new Error(`Request failed: ${requestResult.extract()}`)
  }
  
  const { request, blind } = requestResult.unsafeCoerce()
  
  // Send request.data to server...
  
  // SERVER: Step 2 - Create registration response
  console.log('SERVER: Creating registration response...')
  
  // Server generates or retrieves its keys
  const server_public_key = new Uint8Array(config.ake.Npk)
  const oprf_seed = new Uint8Array(32)
  crypto.getRandomValues(server_public_key)
  crypto.getRandomValues(oprf_seed)
  
  const responseResult = await ops.createResponse(
    request,
    server_public_key,
    oprf_seed
  )
  
  if (responseResult.isLeft()) {
    throw new Error(`Response failed: ${responseResult.extract()}`)
  }
  
  const response = responseResult.unsafeCoerce()
  
  // Send response back to client...
  
  // CLIENT: Step 3 - Finalize registration
  console.log('CLIENT: Finalizing registration...')
  
  const server_identity = new TextEncoder().encode(serverDomain)
  const client_identity = new TextEncoder().encode(username)
  
  const deriveKeyPair = async (seed: Uint8Array) => {
    try {
      const keypair = await config.ake.deriveDHKeyPair(seed)
      return Right({
        private: keypair.private_key,
        public: keypair.public_key
      })
    } catch (e) {
      return Left(e as Error)
    }
  }
  
  const finalizeResult = await ops.finalizeRequest(
    password,
    blind,
    response,
    server_identity,
    client_identity,
    IdentityKSFFn,
    deriveKeyPair
  )
  
  if (finalizeResult.isLeft()) {
    throw new Error(`Finalization failed: ${finalizeResult.extract()}`)
  }
  
  const { record, export_key } = finalizeResult.unsafeCoerce()
  
  console.log('Registration complete!')
  console.log('Client public key:', record.client_public_key.length, 'bytes')
  console.log('Masking key:', record.masking_key.length, 'bytes')
  console.log('Envelope nonce:', record.envelope.nonce.length, 'bytes')
  console.log('Envelope auth tag:', record.envelope.auth_tag.length, 'bytes')
  console.log('Export key:', export_key.length, 'bytes')
  
  // SERVER: Store record for user
  // await database.storeRegistrationRecord(username, record)
  
  return { record, export_key }
}

registerUser().catch(console.error)
```

---

## API Reference

### `createRegistrationOps(config: Config): BoundRegistrationOps`

Creates bound registration operations for a specific OPAQUE configuration.

**Parameters**:

- `config: Config` - OPAQUE configuration (from `OpaqueConfig`)

**Returns**: `BoundRegistrationOps`

```typescript
interface BoundRegistrationOps {
  createRequest: (password: Uint8Array) => Promise<Either<Error, RegistrationRequestResult>>
  createResponse: (
    request: { data: Uint8Array },
    server_public_key: Uint8Array,
    oprf_seed: Uint8Array
  ) => Promise<Either<Error, RegistrationResponse>>
  finalizeRequest: (
    password: Uint8Array,
    blind: Uint8Array,
    response: RegistrationResponse,
    server_identity: Uint8Array,
    client_identity: Uint8Array,
    ksf: KSFFn,
    deriveKeyPair: (seed: Uint8Array) => Promise<Either<Error, { private: Uint8Array; public: Uint8Array }>>
  ) => Promise<Either<Error, RegistrationFinalizeResult>>
}
```

---

## Key Stretching Functions

### Identity KSF (No Stretching)

```typescript
import { IdentityKSFFn } from './thecrypto.js'

// Use in finalizeRequest
const result = await ops.finalizeRequest(
  password, blind, response,
  server_identity, client_identity,
  IdentityKSFFn,  // No additional stretching
  deriveKeyPair
)
```

### Scrypt KSF (Recommended)

```typescript
import { ScryptKSFFn } from './thecrypto.js'

// Use in finalizeRequest
const result = await ops.finalizeRequest(
  password, blind, response,
  server_identity, client_identity,
  ScryptKSFFn,  // Additional Scrypt hardening
  deriveKeyPair
)
```

**Scrypt Parameters**:

- N: 32768 (2^15)
- r: 8
- p: 1

---

## Security Considerations

### Password Never Revealed

The password is never sent to the server in plaintext. It's blinded using OPRF before transmission.

### Server Cannot Offline Attack

Even if the server is compromised, it cannot perform offline dictionary attacks on stored records because:

1. The OPRF output is required (which requires the password)
2. The envelope is authenticated with a MAC derived from the randomized password

### Identity Binding

Server and client identities are bound to the envelope, preventing credential theft attacks where an attacker substitutes identities.

### Randomized Password

The randomized password is derived using:

```ts
randomized_pwd = KSF(HKDF-Extract("", OPRF_output))
```

This ensures that even with the same password, different OPRF outputs result in different randomized passwords.

---

## Error Handling

All functions return `Either<Error, T>` for explicit error handling:

```typescript
const result = await ops.createRequest(password)

if (result.isLeft()) {
  // Handle error
  const error = result.extract()
  console.error('Operation failed:', error.message)
  return
}

// Success - extract value
const value = result.unsafeCoerce()
// or safely:
const value = result.extract()
```

---

## Testing

Comprehensive tests are available in `test/registration-rfc9807.test.ts`:

```bash
npm test -- --testPathPattern=registration
```

Test coverage includes:

- Registration request creation
- Registration response creation
- Registration finalization
- Round-trip registration
- Multiple OPAQUE configurations (P256, P384, P521)
- RFC 9807 message structure verification

---

## RFC 9807 Compliance Checklist

- [x] **Section 5.1**: Message structures (RegistrationRequest, RegistrationResponse, RegistrationRecord)
- [x] **Section 5.2**: Registration functions (CreateRegistrationRequest, CreateRegistrationResponse, FinalizeRequest)
- [x] **Section 3.3**: Randomized password derivation
- [x] **Section 5.1**: Envelope structure and authentication
- [x] **Proper label strings**: "OprfKey", "MaskingKey", "AuthKey", "ExportKey", "PrivateKey"
- [x] **OPRF RFC 9497**: Updated OPRF implementation
- [x] **Functional programming**: Either monads, currying, side effect management

---

## Related Documentation

- [OPRF RFC 9497 Compliance](./OPRF_AUDIT.md)
- [Envelope Operations RFC 9807](./ENVELOPE_RFC9807.md)
- [Functional Programming Guidelines](./FUNCTIONAL_GUIDELINES.md)
- [RFC 9497 Compliance](./RFC9497_COMPLIANCE.md)

---

## Changelog

**v1.0** (February 6, 2026)

- Initial documentation
- RFC 9807 compliant registration flow
- Functional programming implementation
- Comprehensive API reference and examples
