// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// Functional Registration Operations with RFC 9807 compliance

import { Either } from 'purify-ts'
import { curry2, curry4, curry8, tryCatchAsync } from './functional-utils.js'
import { opaqueLogger } from './opaque-config.js'
import { createOPRFOps } from './oprf-functional.js'
import { createEnvelopeOps, createCleartextCredentials } from './envelope-functional.js'
import { createKDFOps, type HashAlgorithm } from './crypto/index.js'
import { LABELS } from './common.js'
import type { Config } from './config.js'
import type { KSFFn } from './thecrypto.js'
import type { SuiteID } from '@cloudflare/voprf-ts'

// Minimal cuid2-compatible ID generator for tracking (not cryptographic)
const createId = (): string => {
  return `req_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`
}

/**
 * Note: createId is used ONLY for tracking/logging IDs (requestId, recordId).
 * All cryptographic randomness (nonces, seeds, keys) uses crypto.getRandomValues().
 */

/**
 * Registration request result
 * RFC 9807 Section 5.1 - RegistrationRequest
 */
export interface RegistrationRequestResult {
  readonly request: {
    readonly data: Uint8Array // Blinded element (OPRF)
  }
  readonly blind: Uint8Array
  readonly requestId: string // cuid2 for tracking (not cryptographic)
}

/**
 * Registration response structure
 * RFC 9807 Section 5.1 - RegistrationResponse
 */
export interface RegistrationResponse {
  readonly data: Uint8Array // OPRF evaluation
  readonly server_public_key: Uint8Array
}

/**
 * Registration record structure
 * RFC 9807 Section 5.1 - RegistrationRecord
 */
export interface RegistrationRecord {
  readonly client_public_key: Uint8Array
  readonly masking_key: Uint8Array
  readonly envelope: {
    readonly nonce: Uint8Array
    readonly auth_tag: Uint8Array
  }
}

/**
 * Registration finalize result
 */
export interface RegistrationFinalizeResult {
  readonly record: RegistrationRecord
  readonly export_key: Uint8Array
  readonly recordId: string // cuid2 for tracking (not cryptographic)
}

/**
 * CreateRegistrationRequest - Step 1 (Client)
 * RFC 9807 Section 5.2
 * 
 * Blinds the password using OPRF to create a registration request.
 * 
 * @sideEffect Crypto RNG (OPRF blind)
 * @sideEffect Logging
 * @sideEffect cuid2 generation (tracking ID only, not cryptographic)
 */
export const createRegistrationRequest = curry2(
  async (
    config: Config,
    password: Uint8Array
  ): Promise<Either<Error, RegistrationRequestResult>> => {
    return tryCatchAsync(async () => {
      const requestId = createId() // SIDE EFFECT: ID for tracking
      opaqueLogger.debug({ message: 'Creating registration request', requestId, config: config.hash.name })
      
      // Get OPRF operations
      const oprfOpsResult = createOPRFOps(config.oprf.id as SuiteID)
      if (oprfOpsResult.isLeft()) throw oprfOpsResult.extract()
      const oprfOps = oprfOpsResult.unsafeCoerce()
      
      // Blind password - SIDE EFFECT: Crypto RNG
      const blindResult = await oprfOps.blind(password)
      if (blindResult.isLeft()) throw blindResult.extract()
      const { blind, blindedElement } = blindResult.unsafeCoerce()
      
      opaqueLogger.debug({ message: 'Registration request created', requestId })
      
      return {
        request: {
          data: blindedElement
        },
        blind,
        requestId
      }
    })
  }
)

/**
 * CreateRegistrationResponse - Step 2 (Server)
 * RFC 9807 Section 5.2
 * 
 * Evaluates the blinded element using OPRF and returns the evaluation
 * along with the server's public key.
 * 
 * @sideEffect Logging
 */
export const createRegistrationResponse = curry4(
  async (
    config: Config,
    request: { data: Uint8Array },
    server_public_key: Uint8Array,
    oprf_seed: Uint8Array
  ): Promise<Either<Error, RegistrationResponse>> => {
    return tryCatchAsync(async () => {
      opaqueLogger.debug({ message: 'Creating registration response', config: config.hash.name })
      
      // Get OPRF operations
      const oprfOpsResult = createOPRFOps(config.oprf.id as SuiteID)
      if (oprfOpsResult.isLeft()) throw oprfOpsResult.extract()
      const oprfOps = oprfOpsResult.unsafeCoerce()
      
      // Get KDF operations
      const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
      if (kdfResult.isLeft()) throw kdfResult.extract()
      const kdf = kdfResult.unsafeCoerce()
      
      // oprf_key_seed = Expand(oprf_seed, "OprfKey", Nseed)
      const expandResult = await kdf.expand(oprf_seed)(
        new Uint8Array(LABELS.OprfKey)
      )(config.constants.Nseed)
      if (expandResult.isLeft()) throw expandResult.extract()
      const oprf_key_seed = expandResult.unsafeCoerce()
      
      // Derive OPRF key pair from seed
      const oprfKeyResult = await oprfOps.deriveKeyPair(oprf_key_seed)
      if (oprfKeyResult.isLeft()) throw oprfKeyResult.extract()
      const oprf_key = oprfKeyResult.unsafeCoerce()
      
      // Evaluate blinded element
      const evaluationResult = await oprfOps.evaluate(oprf_key)(request.data)
      if (evaluationResult.isLeft()) throw evaluationResult.extract()
      const evaluation = evaluationResult.unsafeCoerce()
      
      opaqueLogger.debug({ message: 'Registration response created' })
      
      return {
        data: evaluation,
        server_public_key
      }
    })
  }
)

/**
 * Derive randomized password (RFC 9807 Section 3.3)
 * 
 * Follows the RFC 9807 pattern:
 * 1. Extract: stretched = HKDF-Extract("", oprf_output)
 * 2. Harden: randomized_pwd = KSF(stretched) [or stretched if KSF is Identity]
 * 
 * @sideEffect Logging
 */
const deriveRandomizedPassword = async (
  config: Config,
  oprf_output: Uint8Array,
  ksf: KSFFn
): Promise<Either<Error, Uint8Array>> => {
  return tryCatchAsync(async () => {
    opaqueLogger.debug({ message: 'Deriving randomized password', ksfName: ksf.name })
    
    // Get KDF operations
    const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
    if (kdfResult.isLeft()) throw kdfResult.extract()
    const kdf = kdfResult.unsafeCoerce()
    
    // Extract: stretched = HKDF-Extract("", oprf_output)
    const nosalt = new Uint8Array(config.hash.Nh)
    const stretchedResult = await kdf.extract(nosalt)(oprf_output)
    if (stretchedResult.isLeft()) throw stretchedResult.extract()
    const stretched = stretchedResult.unsafeCoerce()
    
    // Harden: Apply KSF (e.g., Scrypt, Argon2, or Identity)
    // Note: KSF.harden is synchronous in current implementation
    const randomized_pwd = ksf.harden(stretched)
    
    opaqueLogger.debug({ message: 'Randomized password derived' })
    
    return randomized_pwd
  })
}

/**
 * FinalizeRegistrationRequest - Step 3 (Client)
 * RFC 9807 Section 5.2
 * 
 * Finalizes the OPRF output, derives the randomized password,
 * creates an envelope with the credentials, and returns the
 * registration record.
 * 
 * @sideEffect Crypto RNG (envelope nonce)
 * @sideEffect Logging
 * @sideEffect cuid2 generation (tracking ID only, not cryptographic)
 */
export const finalizeRegistrationRequest = curry8(
  async (
    config: Config,
    password: Uint8Array,
    blind: Uint8Array,
    response: RegistrationResponse,
    server_identity: Uint8Array,
    client_identity: Uint8Array,
    ksf: KSFFn,
    deriveKeyPair: (seed: Uint8Array) => Promise<Either<Error, { private: Uint8Array; public: Uint8Array }>>
  ): Promise<Either<Error, RegistrationFinalizeResult>> => {
    return tryCatchAsync(async () => {
      const recordId = createId() // SIDE EFFECT: ID for tracking
      opaqueLogger.debug({ message: 'Finalizing registration request', recordId, config: config.hash.name })
      
      // Get OPRF operations
      const oprfOpsResult = createOPRFOps(config.oprf.id as SuiteID)
      if (oprfOpsResult.isLeft()) throw oprfOpsResult.extract()
      const oprfOps = oprfOpsResult.unsafeCoerce()
      
      // Finalize OPRF
      const oprfOutputResult = await oprfOps.finalize({
        input: password,
        blind,
        evaluation: response.data
      })
      if (oprfOutputResult.isLeft()) throw oprfOutputResult.extract()
      const oprf_output = oprfOutputResult.unsafeCoerce()
      
      // Derive randomized password
      const randomizedPwdResult = await deriveRandomizedPassword(config, oprf_output, ksf)
      if (randomizedPwdResult.isLeft()) throw randomizedPwdResult.extract()
      const randomized_pwd = randomizedPwdResult.unsafeCoerce()
      
      // Create cleartext credentials
      const cleartextCreds = createCleartextCredentials(
        response.server_public_key
      )(
        server_identity
      )(
        client_identity
      )
      
      // Store envelope - SIDE EFFECT: Crypto RNG for nonce
      const envelopeOps = createEnvelopeOps(config)
      const storeResult = await envelopeOps.store(randomized_pwd, cleartextCreds, deriveKeyPair)
      if (storeResult.isLeft()) throw storeResult.extract()
      
      const { envelope, client_public_key, masking_key, export_key } = storeResult.unsafeCoerce()
      
      opaqueLogger.debug({ message: 'Registration finalized', recordId })
      
      return {
        record: {
          client_public_key,
          masking_key,
          envelope
        },
        export_key,
        recordId
      }
    })
  }
)

/**
 * Bound registration operations
 * 
 * All operations are curried and bound to a specific config.
 */
export interface BoundRegistrationOps {
  /**
   * Create a registration request (Client-side, Step 1)
   */
  createRequest: (password: Uint8Array) => Promise<Either<Error, RegistrationRequestResult>>
  
  /**
   * Create a registration response (Server-side, Step 2)
   */
  createResponse: (
    request: { data: Uint8Array },
    server_public_key: Uint8Array,
    oprf_seed: Uint8Array
  ) => Promise<Either<Error, RegistrationResponse>>
  
  /**
   * Finalize registration request (Client-side, Step 3)
   */
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

/**
 * Create bound registration operations
 * @pure
 */
export const createRegistrationOps = (config: Config): BoundRegistrationOps => ({
  createRequest: (password: Uint8Array) => createRegistrationRequest(config)(password),
  createResponse: (request: { data: Uint8Array }, server_public_key: Uint8Array, oprf_seed: Uint8Array) =>
    createRegistrationResponse(config)(request)(server_public_key)(oprf_seed),
  finalizeRequest: (
    password: Uint8Array,
    blind: Uint8Array,
    response: RegistrationResponse,
    server_identity: Uint8Array,
    client_identity: Uint8Array,
    ksf: KSFFn,
    deriveKeyPair: (seed: Uint8Array) => Promise<Either<Error, { private: Uint8Array; public: Uint8Array }>>
  ) =>
    finalizeRegistrationRequest(config)(password)(blind)(response)(server_identity)(client_identity)(ksf)(deriveKeyPair)
})
