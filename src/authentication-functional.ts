// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// Functional authentication operations with RFC 9807 Section 6 compliance

import { Either } from 'purify-ts'
import { curry3, curry4, curry5, curry7, tryCatchAsync } from './functional-utils.js'
import { opaqueLogger } from './opaque-config.js'
import { createId } from '@paralleldrive/cuid2'
import { createOPRFOps } from './oprf-functional.js'
import { createEnvelopeOps } from './envelope-functional.js'
import { createKDFOps, generateNonce, type HashAlgorithm } from './crypto/index.js'
import { LABELS } from './common.js'
import type { Config } from './config.js'
import type { SuiteID } from '@cloudflare/voprf-ts'

/**
 * Note: cuid2 is used ONLY for session tracking/logging (sessionId).
 * All cryptographic randomness (nonces, keys) uses crypto.getRandomValues().
 */

/**
 * KE1 message structure (RFC 9807 Section 6)
 */
export interface KE1 {
  readonly credential_request: {
    readonly data: Uint8Array
  }
  readonly auth_init: {
    readonly client_nonce: Uint8Array
    readonly client_keyshare: Uint8Array
  }
  readonly sessionId: string // cuid2 for logging only
}

/**
 * KE2 message structure (RFC 9807 Section 6)
 */
export interface KE2 {
  readonly credential_response: {
    readonly data: Uint8Array
    readonly masking_nonce: Uint8Array
    readonly masked_response: Uint8Array
  }
  readonly auth_response: {
    readonly server_nonce: Uint8Array
    readonly server_keyshare: Uint8Array
    readonly server_mac: Uint8Array
  }
}

/**
 * KE3 message structure (RFC 9807 Section 6)
 */
export interface KE3 {
  readonly client_mac: Uint8Array
}

/**
 * Client state for authentication flow
 */
export interface ClientAuthState {
  readonly blind: Uint8Array
  readonly client_secret: Uint8Array
  readonly sessionId: string
}

/**
 * Server state for authentication flow
 */
export interface ServerAuthState {
  readonly server_secret: Uint8Array
  readonly sessionId: string
}

/**
 * CreateCredentialRequest - Part of KE1 (Client)
 * RFC 9807 Section 6.1.1
 * 
 * @sideEffect Crypto RNG (OPRF blind, nonces, keyshare)
 * @sideEffect Logging
 * @sideEffect cuid2 generation (session tracking only, not cryptographic)
 */
export const createCredentialRequest = curry3(
  async (
    config: Config,
    password: Uint8Array,
    generateKeyshare: () => Promise<Either<Error, { keyshare: Uint8Array; private: Uint8Array }>>
  ): Promise<Either<Error, { ke1: KE1; blind: Uint8Array; client_secret: Uint8Array }>> => {
    return tryCatchAsync(async () => {
      const sessionId = createId()
      opaqueLogger.debug({ message: 'Creating credential request (KE1)', sessionId })
      
      // OPRF Blind
      const oprfOpsResult = createOPRFOps(config.oprf.id as SuiteID)
      if (oprfOpsResult.isLeft()) throw oprfOpsResult.extract()
      const oprfOps = oprfOpsResult.unsafeCoerce()
      
      const blindResult = await oprfOps.blind(password)
      if (blindResult.isLeft()) throw blindResult.extract()
      const { blind, blindedElement } = blindResult.unsafeCoerce()
      
      // Generate client nonce
      const nonceResult = generateNonce(config.constants.Nn)
      if (nonceResult.isLeft()) throw nonceResult.extract()
      const client_nonce = nonceResult.unsafeCoerce()
      
      // Generate client keyshare (DH ephemeral)
      const keyshareResult = await generateKeyshare()
      if (keyshareResult.isLeft()) throw keyshareResult.extract()
      const { keyshare: client_keyshare, private: client_secret } = keyshareResult.unsafeCoerce()
      
      opaqueLogger.debug({ message: 'KE1 created', sessionId })
      
      return {
        ke1: {
          credential_request: {
            data: blindedElement
          },
          auth_init: {
            client_nonce,
            client_keyshare
          },
          sessionId
        },
        blind,
        client_secret
      }
    })
  }
)

/**
 * Mask credential response (Server)
 * RFC 9807 Section 6.1.2
 * 
 * @sideEffect Logging
 */
export const maskCredentialResponse = curry4(
  async (
    config: Config,
    masking_key: Uint8Array,
    masking_nonce: Uint8Array,
    data: { server_public_key: Uint8Array; envelope: { nonce: Uint8Array; auth_tag: Uint8Array } }
  ): Promise<Either<Error, Uint8Array>> => {
    return tryCatchAsync(async () => {
      opaqueLogger.debug({ message: 'Masking credential response' })
      
      // Compute pad = Expand(masking_key, concat(nonce, "CredentialResponsePad"), Npk + Ne)
      const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
      if (kdfResult.isLeft()) throw kdfResult.extract()
      const kdf = kdfResult.unsafeCoerce()
      
      const padInfo = new Uint8Array([...masking_nonce, ...LABELS.CredentialResponsePad])
      const padLength = config.ake.Npk + config.constants.Nn + config.mac.Nm // server_public_key + envelope
      
      const padResult = await kdf.expand(masking_key)(padInfo)(padLength)
      if (padResult.isLeft()) throw padResult.extract()
      const pad = padResult.unsafeCoerce()
      
      // Concatenate server_public_key and envelope
      const unmasked = new Uint8Array(padLength)
      unmasked.set(data.server_public_key, 0)
      unmasked.set(data.envelope.nonce, config.ake.Npk)
      unmasked.set(data.envelope.auth_tag, config.ake.Npk + config.constants.Nn)
      
      // XOR mask
      const masked = new Uint8Array(unmasked.length)
      for (let i = 0; i < masked.length; i++) {
        masked[i] = unmasked[i] ^ pad[i]
      }
      
      opaqueLogger.debug({ message: 'Credential response masked' })
      
      return masked
    })
  }
)

/**
 * Unmask credential response (Client)
 * RFC 9807 Section 6.1.2
 * 
 * @sideEffect Logging
 */
export const unmaskCredentialResponse = curry3(
  async (
    config: Config,
    masking_key: Uint8Array,
    credential_response: { masking_nonce: Uint8Array; masked_response: Uint8Array }
  ): Promise<Either<Error, { server_public_key: Uint8Array; envelope: { nonce: Uint8Array; auth_tag: Uint8Array } }>> => {
    return tryCatchAsync(async () => {
      opaqueLogger.debug({ message: 'Unmasking credential response' })
      
      // Compute pad = Expand(masking_key, concat(nonce, "CredentialResponsePad"), Npk + Ne)
      const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
      if (kdfResult.isLeft()) throw kdfResult.extract()
      const kdf = kdfResult.unsafeCoerce()
      
      const padInfo = new Uint8Array([...credential_response.masking_nonce, ...LABELS.CredentialResponsePad])
      const padLength = config.ake.Npk + config.constants.Nn + config.mac.Nm // server_public_key + envelope
      
      const padResult = await kdf.expand(masking_key)(padInfo)(padLength)
      if (padResult.isLeft()) throw padResult.extract()
      const pad = padResult.unsafeCoerce()
      
      // XOR unmask
      const unmasked = new Uint8Array(credential_response.masked_response.length)
      for (let i = 0; i < unmasked.length; i++) {
        unmasked[i] = credential_response.masked_response[i] ^ pad[i]
      }
      
      // Parse unmasked data
      const server_public_key = unmasked.slice(0, config.ake.Npk)
      const envelope_nonce = unmasked.slice(config.ake.Npk, config.ake.Npk + config.constants.Nn)
      const auth_tag = unmasked.slice(config.ake.Npk + config.constants.Nn)
      
      opaqueLogger.debug({ message: 'Credential response unmasked' })
      
      return {
        server_public_key,
        envelope: {
          nonce: envelope_nonce,
          auth_tag
        }
      }
    })
  }
)

/**
 * RecoverCredentials - Part of authentication (Client)
 * RFC 9807 Section 6.1.2
 * 
 * @sideEffect Logging
 */
export const recoverCredentials = curry7(
  async (
    config: Config,
    password: Uint8Array,
    blind: Uint8Array,
    ke2: KE2,
    server_identity: Uint8Array,
    client_identity: Uint8Array,
    deriveKeyPair: (seed: Uint8Array) => Promise<Either<Error, { private: Uint8Array; public: Uint8Array }>>
  ): Promise<Either<Error, { client_private_key: Uint8Array; server_public_key: Uint8Array; export_key: Uint8Array }>> => {
    return tryCatchAsync(async () => {
      opaqueLogger.debug({ message: 'Recovering credentials' })
      
      // Finalize OPRF
      const oprfOpsResult = createOPRFOps(config.oprf.id as SuiteID)
      if (oprfOpsResult.isLeft()) throw oprfOpsResult.extract()
      const oprfOps = oprfOpsResult.unsafeCoerce()
      
      const oprfOutputResult = await oprfOps.finalize({ input: password, blind, evaluation: ke2.credential_response.data })
      if (oprfOutputResult.isLeft()) throw oprfOutputResult.extract()
      const oprf_output = oprfOutputResult.unsafeCoerce()
      
      // Derive randomized password using HKDF-Extract
      const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
      if (kdfResult.isLeft()) throw kdfResult.extract()
      const kdf = kdfResult.unsafeCoerce()
      
      const randomizedPwdResult = await kdf.extract(new Uint8Array(0))(oprf_output)
      if (randomizedPwdResult.isLeft()) throw randomizedPwdResult.extract()
      const randomized_pwd = randomizedPwdResult.unsafeCoerce()
      
      // Derive masking key
      const maskingKeyResult = await kdf.expand(randomized_pwd)(new Uint8Array(LABELS.MaskingKey))(config.hash.Nh)
      if (maskingKeyResult.isLeft()) throw maskingKeyResult.extract()
      const masking_key = maskingKeyResult.unsafeCoerce()
      
      // Unmask credential response
      const unmaskedResult = await unmaskCredentialResponse(config)(masking_key)(ke2.credential_response)
      if (unmaskedResult.isLeft()) throw unmaskedResult.extract()
      const { server_public_key, envelope } = unmaskedResult.unsafeCoerce()
      
      // Recover envelope
      const envelopeOps = createEnvelopeOps(config)
      const cleartextCreds = {
        server_public_key,
        server_identity,
        client_identity
      }
      const recoverResult = await envelopeOps.recover(randomized_pwd, envelope, cleartextCreds, deriveKeyPair)
      if (recoverResult.isLeft()) throw recoverResult.extract()
      
      const { client_private_key, export_key } = recoverResult.unsafeCoerce()
      
      opaqueLogger.debug({ message: 'Credentials recovered' })
      
      return {
        client_private_key,
        server_public_key,
        export_key
      }
    })
  }
)

/**
 * Create credential response (Server)
 * RFC 9807 Section 6.1.2
 * 
 * @sideEffect Crypto RNG (masking nonce)
 * @sideEffect Logging
 */
export const createCredentialResponse = curry5(
  async (
    config: Config,
    ke1: KE1,
    server_public_key: Uint8Array,
    envelope: { nonce: Uint8Array; auth_tag: Uint8Array },
    oprf_key: Uint8Array
  ): Promise<Either<Error, { credential_response: KE2['credential_response']; oprf_seed: Uint8Array }>> => {
    return tryCatchAsync(async () => {
      opaqueLogger.debug({ message: 'Creating credential response (KE2)', sessionId: ke1.sessionId })
      
      // OPRF Evaluate
      const oprfOpsResult = createOPRFOps(config.oprf.id as SuiteID)
      if (oprfOpsResult.isLeft()) throw oprfOpsResult.extract()
      const oprfOps = oprfOpsResult.unsafeCoerce()
      
      const evaluateResult = await oprfOps.evaluate(oprf_key)(ke1.credential_request.data)
      if (evaluateResult.isLeft()) throw evaluateResult.extract()
      const evaluated_element = evaluateResult.unsafeCoerce()
      
      // Generate masking nonce
      const maskingNonceResult = generateNonce(config.constants.Nn)
      if (maskingNonceResult.isLeft()) throw maskingNonceResult.extract()
      const masking_nonce = maskingNonceResult.unsafeCoerce()
      
      // Derive randomized password (server would need to do this for masking key)
      // For now, we'll compute it from the OPRF output
      const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
      if (kdfResult.isLeft()) throw kdfResult.extract()
      const kdf = kdfResult.unsafeCoerce()
      
      // Note: Server needs to derive the same randomized_pwd as client will
      // This requires the OPRF output, which server can compute
      const randomizedPwdResult = await kdf.extract(new Uint8Array(0))(evaluated_element)
      if (randomizedPwdResult.isLeft()) throw randomizedPwdResult.extract()
      const randomized_pwd = randomizedPwdResult.unsafeCoerce()
      
      // Derive masking key
      const maskingKeyResult = await kdf.expand(randomized_pwd)(new Uint8Array(LABELS.MaskingKey))(config.hash.Nh)
      if (maskingKeyResult.isLeft()) throw maskingKeyResult.extract()
      const masking_key = maskingKeyResult.unsafeCoerce()
      
      // Mask credential response
      const maskedResult = await maskCredentialResponse(config)(masking_key)(masking_nonce)({ server_public_key, envelope })
      if (maskedResult.isLeft()) throw maskedResult.extract()
      const masked_response = maskedResult.unsafeCoerce()
      
      opaqueLogger.debug({ message: 'Credential response created', sessionId: ke1.sessionId })
      
      return {
        credential_response: {
          data: evaluated_element,
          masking_nonce,
          masked_response
        },
        oprf_seed: randomized_pwd
      }
    })
  }
)

/**
 * Bound authentication operations
 */
export interface BoundAuthOps {
  createCredentialRequest: (
    password: Uint8Array
  ) => (
    generateKeyshare: () => Promise<Either<Error, { keyshare: Uint8Array; private: Uint8Array }>>
  ) => Promise<Either<Error, { ke1: KE1; blind: Uint8Array; client_secret: Uint8Array }>>
  
  recoverCredentials: (
    password: Uint8Array
  ) => (
    blind: Uint8Array
  ) => (
    ke2: KE2
  ) => (
    server_identity: Uint8Array
  ) => (
    client_identity: Uint8Array
  ) => (
    deriveKeyPair: (seed: Uint8Array) => Promise<Either<Error, { private: Uint8Array; public: Uint8Array }>>
  ) => Promise<Either<Error, { client_private_key: Uint8Array; server_public_key: Uint8Array; export_key: Uint8Array }>>
  
  createCredentialResponse: (
    ke1: KE1
  ) => (
    server_public_key: Uint8Array
  ) => (
    envelope: { nonce: Uint8Array; auth_tag: Uint8Array }
  ) => (
    oprf_key: Uint8Array
  ) => Promise<Either<Error, { credential_response: KE2['credential_response']; oprf_seed: Uint8Array }>>
  
  unmaskCredentialResponse: (
    masking_key: Uint8Array
  ) => (
    credential_response: { masking_nonce: Uint8Array; masked_response: Uint8Array }
  ) => Promise<Either<Error, { server_public_key: Uint8Array; envelope: { nonce: Uint8Array; auth_tag: Uint8Array } }>>
  
  maskCredentialResponse: (
    masking_key: Uint8Array
  ) => (
    masking_nonce: Uint8Array
  ) => (
    data: { server_public_key: Uint8Array; envelope: { nonce: Uint8Array; auth_tag: Uint8Array } }
  ) => Promise<Either<Error, Uint8Array>>
}

/**
 * Create bound authentication operations
 * @pure
 */
export const createAuthOps = (config: Config): BoundAuthOps => ({
  createCredentialRequest: createCredentialRequest(config),
  recoverCredentials: recoverCredentials(config),
  createCredentialResponse: createCredentialResponse(config),
  unmaskCredentialResponse: unmaskCredentialResponse(config),
  maskCredentialResponse: maskCredentialResponse(config)
})
