// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// Functional 3DH key schedule operations (RFC 9807 Section 6.2)

import { Either } from 'purify-ts'
import { curry3, curry4, tryCatchAsync } from './functional-utils.js'
import { opaqueLogger } from './opaque-config.js'
import { createKDFOps, createHashOps } from './crypto/index.js'
import { LABELS } from './common.js'
import type { Config } from './config.js'
import type { KE1, KE2 } from './authentication-functional.js'
import type { HashAlgorithm } from './crypto/index.js'

/**
 * Serialize integer to 2-byte big-endian (I2OSP)
 * RFC 9807 uses I2OSP(len, 2) for length encoding
 * 
 * @pure
 */
const i2osp2 = (value: number): Uint8Array => {
  return new Uint8Array([value >> 8, value & 0xff])
}

/**
 * Construct preamble (RFC 9807 Section 6.2.2)
 * 
 * Preamble format:
 *   "RFC9807" || I2OSP(len(context), 2) || context ||
 *   I2OSP(len(client_identity), 2) || client_identity ||
 *   ke1 || I2OSP(len(server_identity), 2) || server_identity ||
 *   ke2.credential_response || ke2.auth_response.server_nonce ||
 *   ke2.auth_response.server_keyshare
 * 
 * @pure (pure computation, no I/O or side effects)
 * @param context Optional context string
 * @param client_identity Client identity
 * @param ke1 KE1 message
 * @param server_identity Server identity
 * @param ke2 KE2 message
 */
export const constructPreamble = (
  context: Uint8Array,
  client_identity: Uint8Array,
  ke1: KE1,
  server_identity: Uint8Array,
  ke2: KE2
): Uint8Array => {
  opaqueLogger.debug({ message: 'Constructing preamble per RFC 9807 Section 6.2.2' })
  
  // Serialize KE1 components
  const ke1_serialized = new Uint8Array([
    ...ke1.credential_request.data,
    ...ke1.auth_init.client_nonce,
    ...ke1.auth_init.client_keyshare
  ])
  
  // Serialize credential_response components
  const credential_response_serialized = new Uint8Array([
    ...ke2.credential_response.data,
    ...ke2.credential_response.masking_nonce,
    ...ke2.credential_response.masked_response
  ])
  
  // Construct preamble per RFC 9807 Section 6.2.2
  const preamble = new Uint8Array([
    ...LABELS.Version,  // "RFC9807"
    ...i2osp2(context.length),
    ...context,
    ...i2osp2(client_identity.length),
    ...client_identity,
    ...ke1_serialized,
    ...i2osp2(server_identity.length),
    ...server_identity,
    ...credential_response_serialized,
    ...ke2.auth_response.server_nonce,
    ...ke2.auth_response.server_keyshare
  ])
  
  opaqueLogger.debug({ message: 'Preamble constructed', length: preamble.length })
  
  return preamble
}

/**
 * Triple-DH IKM computation (RFC 9807 Section 6.2.1)
 * 
 * TripleDHIKM(sk1, pk1, sk2, pk2, sk3, pk3):
 *   dh1 = SerializePublicKey(sk1 * pk1)
 *   dh2 = SerializePublicKey(sk2 * pk2)
 *   dh3 = SerializePublicKey(sk3 * pk3)
 *   Output concat(dh1, dh2, dh3)
 * 
 * Note: The actual DH computations are done externally.
 * This function just concatenates the three DH shares.
 * 
 * @sideEffect Logging only
 * @param dh1 First DH share
 * @param dh2 Second DH share
 * @param dh3 Third DH share
 */
export const computeTripleDHIKM = curry3(
  async (
    dh1: Uint8Array,
    dh2: Uint8Array,
    dh3: Uint8Array
  ): Promise<Either<Error, Uint8Array>> => {
    return tryCatchAsync(async () => {
      opaqueLogger.debug({ message: 'Computing Triple-DH IKM' })
      
      // Concatenate all three DH shares
      const ikm = new Uint8Array([...dh1, ...dh2, ...dh3])
      
      opaqueLogger.debug({ message: 'Triple-DH IKM computed', length: ikm.length })
      
      return ikm
    })
  }
)

/**
 * Derive-Secret helper (RFC 9807 pattern)
 * 
 * Uses HKDF-Expand with label and context
 * 
 * @sideEffect Logging
 * @param config OPAQUE configuration
 * @param prk Pseudorandom key from Extract
 * @param label Label string (e.g., "HandshakeSecret")
 * @param context Context data (typically hash of preamble or empty)
 */
const deriveSecret = curry4(
  async (
    config: Config,
    prk: Uint8Array,
    label: readonly number[],
    context: Uint8Array
  ): Promise<Either<Error, Uint8Array>> => {
    const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
    if (kdfResult.isLeft()) return kdfResult
    
    const kdf = kdfResult.unsafeCoerce()
    
    // HKDF-Expand-Label pattern: info = label || context
    const info = new Uint8Array([...label, ...context])
    
    return await kdf.expand(prk)(info)(config.hash.Nh)
  }
)

/**
 * DeriveKeys - Derive all authentication keys (RFC 9807 Section 6.2.3)
 * 
 * DeriveKeys(ikm, preamble):
 *   prk = Extract("", ikm)
 *   handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
 *   session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
 *   Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
 *   Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
 *   Output (Km2, Km3, session_key)
 * 
 * @sideEffect Logging
 * @param config OPAQUE configuration
 * @param ikm Input keying material (Triple-DH output)
 * @param preamble Transcript preamble
 */
export const deriveKeys = curry3(
  async (
    config: Config,
    ikm: Uint8Array,
    preamble: Uint8Array
  ): Promise<Either<Error, {
    Km2: Uint8Array
    Km3: Uint8Array
    session_key: Uint8Array
  }>> => {
    return tryCatchAsync(async () => {
      opaqueLogger.debug({ message: 'Deriving keys from 3DH per RFC 9807 Section 6.2.3' })
      
      // Get crypto operations
      const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
      if (kdfResult.isLeft()) throw kdfResult.extract()
      const kdf = kdfResult.unsafeCoerce()
      
      const hashResult = createHashOps(config.hash.name as HashAlgorithm)
      if (hashResult.isLeft()) throw hashResult.extract()
      const hashOps = hashResult.unsafeCoerce()
      
      // Hash preamble
      const preambleHashResult = await hashOps.hash(preamble)
      if (preambleHashResult.isLeft()) throw preambleHashResult.extract()
      const preamble_hash = preambleHashResult.unsafeCoerce()
      
      // Extract: prk = HKDF-Extract("", ikm)
      const prkResult = await kdf.extract(new Uint8Array(0))(ikm)
      if (prkResult.isLeft()) throw prkResult.extract()
      const prk = prkResult.unsafeCoerce()
      
      // handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
      const handshakeSecretResult = await deriveSecret(config)(prk)(LABELS.HandshakeSecret)(preamble_hash)
      if (handshakeSecretResult.isLeft()) throw handshakeSecretResult.extract()
      const handshake_secret = handshakeSecretResult.unsafeCoerce()
      
      // session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
      const sessionKeyResult = await deriveSecret(config)(prk)(LABELS.SessionKey)(preamble_hash)
      if (sessionKeyResult.isLeft()) throw sessionKeyResult.extract()
      const session_key = sessionKeyResult.unsafeCoerce()
      
      // Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
      const Km2Result = await deriveSecret(config)(handshake_secret)(LABELS.ServerMAC)(new Uint8Array(0))
      if (Km2Result.isLeft()) throw Km2Result.extract()
      const Km2 = Km2Result.unsafeCoerce()
      
      // Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
      const Km3Result = await deriveSecret(config)(handshake_secret)(LABELS.ClientMAC)(new Uint8Array(0))
      if (Km3Result.isLeft()) throw Km3Result.extract()
      const Km3 = Km3Result.unsafeCoerce()
      
      opaqueLogger.debug({
        message: 'Keys derived from 3DH',
        Km2Length: Km2.length,
        Km3Length: Km3.length,
        sessionKeyLength: session_key.length
      })
      
      return { Km2, Km3, session_key }
    })
  }
)

/**
 * Bound 3DH operations with config
 */
export interface Bound3DHOps {
  /**
   * Construct preamble from message components
   */
  constructPreamble: (
    context: Uint8Array,
    client_identity: Uint8Array,
    ke1: KE1,
    server_identity: Uint8Array,
    ke2: KE2
  ) => Uint8Array
  
  /**
   * Compute Triple-DH IKM from three DH shares
   */
  computeTripleDHIKM: (
    dh1: Uint8Array,
    dh2: Uint8Array,
    dh3: Uint8Array
  ) => Promise<Either<Error, Uint8Array>>
  
  /**
   * Derive authentication keys from IKM and preamble
   */
  deriveKeys: (
    ikm: Uint8Array,
    preamble: Uint8Array
  ) => Promise<Either<Error, {
    Km2: Uint8Array
    Km3: Uint8Array
    session_key: Uint8Array
  }>>
}

/**
 * Create bound 3DH operations with config
 * 
 * @pure (returns object with bound functions)
 * @param config OPAQUE configuration
 */
export const create3DHOps = (config: Config): Bound3DHOps => ({
  constructPreamble,
  computeTripleDHIKM: async (dh1, dh2, dh3) => await computeTripleDHIKM(dh1)(dh2)(dh3),
  deriveKeys: async (ikm, preamble) => await deriveKeys(config)(ikm)(preamble)
})
