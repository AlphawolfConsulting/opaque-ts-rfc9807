import { Either, Right, Left } from 'purify-ts'
import { curry3, curry4, tryCatchAsync } from '../functional-utils.js'
import { opaqueLogger } from '../opaque-config.js'
import { extract, expand } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { sha384, sha512 } from '@noble/hashes/sha512'
import { sha1 } from '@noble/hashes/sha1'
import type { HashAlgorithm } from './hash-functional.js'

/**
 * KDF configuration
 */
export interface KDFConfig {
  readonly hash: HashAlgorithm
  readonly hashFn: typeof sha256 | typeof sha384 | typeof sha512 | typeof sha1
  readonly hashLen: number
}

/**
 * Create KDF configuration
 * @pure
 */
export const createKDFConfig = (hash: HashAlgorithm): Either<Error, KDFConfig> => {
  const configs: Partial<Record<HashAlgorithm, { hashFn: typeof sha256 | typeof sha384 | typeof sha512 | typeof sha1, hashLen: number }>> = {
    'SHA-1': { hashFn: sha1, hashLen: 20 },
    'SHA-256': { hashFn: sha256, hashLen: 32 },
    'SHA-384': { hashFn: sha384, hashLen: 48 },
    'SHA-512': { hashFn: sha512, hashLen: 64 }
  }
  
  const config = configs[hash]
  if (!config) {
    return Left(new Error(`Unsupported hash for KDF: ${hash}`))
  }
  
  return Right({
    hash,
    hashFn: config.hashFn,
    hashLen: config.hashLen
  })
}

/**
 * HKDF Extract
 * 
 * @sideEffect Logging
 * @param config KDF configuration
 * @param salt Salt value (can be empty/zero)
 * @param ikm Input keying material
 * @returns Either<Error, Uint8Array> PRK (pseudorandom key)
 */
export const hkdfExtract = curry3(
  async (
    config: KDFConfig,
    salt: Uint8Array,
    ikm: Uint8Array
  ): Promise<Either<Error, Uint8Array>> => {
    return tryCatchAsync(async () => {
      opaqueLogger.debug({ message: 'HKDF Extract', hash: config.hash, saltLength: salt.length, ikmLength: ikm.length })
      
      // SIDE EFFECT: hkdf extract (pure computation, but we log it)
      const prk = extract(config.hashFn, ikm, salt)
      
      opaqueLogger.debug({ message: 'HKDF Extract complete', prkLength: prk.length })
      
      return prk
    })
  }
)

/**
 * HKDF Expand
 * 
 * @sideEffect Logging
 * @param config KDF configuration
 * @param prk Pseudorandom key from Extract
 * @param info Application-specific info
 * @param length Desired output length
 * @returns Either<Error, Uint8Array> OKM (output keying material)
 */
export const hkdfExpand = curry4(
  async (
    config: KDFConfig,
    prk: Uint8Array,
    info: Uint8Array,
    length: number
  ): Promise<Either<Error, Uint8Array>> => {
    return tryCatchAsync(async () => {
      opaqueLogger.debug({ message: 'HKDF Expand', hash: config.hash, prkLength: prk.length, infoLength: info.length, outputLength: length })
      
      // SIDE EFFECT: hkdf expand (pure computation, but we log it)
      const okm = expand(config.hashFn, prk, info, length)
      
      opaqueLogger.debug({ message: 'HKDF Expand complete', okmLength: okm.length })
      
      return okm
    })
  }
)

/**
 * HKDF (combined Extract + Expand)
 * 
 * @sideEffect Logging
 */
export const hkdfDerive = async (
  config: KDFConfig,
  salt: Uint8Array,
  ikm: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Either<Error, Uint8Array>> => {
  const extractResult = await hkdfExtract(config)(salt)(ikm)
  if (extractResult.isLeft()) {
    return extractResult
  }
  
  const prk = extractResult.unsafeCoerce()
  return hkdfExpand(config)(prk)(info)(length)
}

/**
 * Bound KDF operations
 */
export interface BoundKDFOps {
  extract: (salt: Uint8Array) => (ikm: Uint8Array) => Promise<Either<Error, Uint8Array>>
  expand: (prk: Uint8Array) => (info: Uint8Array) => (length: number) => Promise<Either<Error, Uint8Array>>
  derive: (salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number) => Promise<Either<Error, Uint8Array>>
  config: KDFConfig
}

/**
 * Create bound KDF operations
 * @pure
 */
export const createBoundKDFOps = (config: KDFConfig): BoundKDFOps => ({
  extract: hkdfExtract(config),
  expand: hkdfExpand(config),
  derive: (salt, ikm, info, length) => hkdfDerive(config, salt, ikm, info, length),
  config
})

/**
 * Helper to create KDF operations with error handling
 */
export const createKDFOps = (hash: HashAlgorithm): Either<Error, BoundKDFOps> =>
  createKDFConfig(hash).map(createBoundKDFOps)

/**
 * HKDF-Expand-Label (RFC 9807 pattern)
 * 
 * @param config KDF configuration
 * @param prk Pseudorandom key
 * @param label Label as byte array (e.g., "HandshakeSecret")
 * @param context Additional context
 * @param length Output length
 */
export const hkdfExpandLabel = async (
  config: KDFConfig,
  prk: Uint8Array,
  label: readonly number[], // Label as byte array
  context: readonly number[], // Context as byte array
  length: number
): Promise<Either<Error, Uint8Array>> => {
  // Construct HkdfLabel structure
  const labelBytes = new Uint8Array([
    length >> 8, length & 0xff, // uint16 length
    ...label,
    ...context
  ])
  
  return hkdfExpand(config)(prk)(labelBytes)(length)
}
