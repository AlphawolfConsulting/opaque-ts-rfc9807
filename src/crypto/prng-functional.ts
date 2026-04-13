import { Either } from 'purify-ts'
import { tryCatch } from '../functional-utils.js'
import { opaqueLogger } from '../opaque-config.js'

/**
 * Generate cryptographically secure random bytes
 * 
 * @sideEffect Crypto RNG
 * @sideEffect Logging
 * @param numBytes Number of random bytes to generate
 * @returns Either<Error, Uint8Array> Random bytes
 */
export const generateRandomBytes = (numBytes: number): Either<Error, Uint8Array> => {
  return tryCatch(() => {
    opaqueLogger.debug({ message: 'Generating random bytes', numBytes })
    
    if (numBytes <= 0) {
      throw new Error('numBytes must be positive')
    }
    
    // SIDE EFFECT: crypto.getRandomValues
    const randomBytes = crypto.getRandomValues(new Uint8Array(numBytes))
    
    opaqueLogger.debug({ message: 'Random bytes generated', length: randomBytes.length })
    
    return randomBytes
  })
}

/**
 * Generate random nonce (alias for clarity)
 * 
 * @sideEffect Crypto RNG
 * @sideEffect Logging
 */
export const generateNonce = generateRandomBytes

/**
 * Generate random seed (alias for clarity)
 * 
 * @sideEffect Crypto RNG
 * @sideEffect Logging
 */
export const generateSeed = generateRandomBytes

/**
 * PRNG operations
 */
export interface PRNGOps {
  randomBytes: (numBytes: number) => Either<Error, Uint8Array>
  nonce: (numBytes: number) => Either<Error, Uint8Array>
  seed: (numBytes: number) => Either<Error, Uint8Array>
}

/**
 * Create PRNG operations
 * @pure (returns functions with side effects)
 */
export const createPRNGOps = (): PRNGOps => ({
  randomBytes: generateRandomBytes,
  nonce: generateNonce,
  seed: generateSeed
})
