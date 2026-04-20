import type { Either } from 'purify-ts'
import { Right, Left } from 'purify-ts'
import { curry2, tryCatchAsync } from '../functional-utils.js'
import { opaqueLogger } from '../opaque-config.js'

/**
 * Hash configuration
 */
export interface HashConfig {
    readonly name: HashAlgorithm
    readonly Nh: number // Output size in bytes
}

export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'

/**
 * Create hash configuration
 * @pure
 */
export const createHashConfig = (name: HashAlgorithm): Either<Error, HashConfig> => {
    const sizes: Record<HashAlgorithm, number> = {
        'SHA-1': 20,
        'SHA-256': 32,
        'SHA-384': 48,
        'SHA-512': 64
    }

    if (!(name in sizes)) {
        return Left(new Error(`Invalid hash algorithm: ${name}`))
    }

    return Right({
        name,
        Nh: sizes[name]
    })
}

/**
 * Hash a message
 *
 * @sideEffect Web Crypto API
 * @sideEffect Logging
 * @param config Hash configuration
 * @param message Message to hash
 * @returns Either<Error, Uint8Array> Hash digest
 */
export const hashMessage = curry2(
    async (config: HashConfig, message: Uint8Array): Promise<Either<Error, Uint8Array>> => {
        return tryCatchAsync(async () => {
            opaqueLogger.debug({
                message: `Hashing message with ${config.name}`,
                algorithm: config.name,
                messageLength: message.length
            })

            // SIDE EFFECT: crypto.subtle.digest
            const digest = await crypto.subtle.digest(config.name, message)
            const result = new Uint8Array(digest)

            opaqueLogger.debug({ message: 'Hash complete', digestLength: result.length })

            return result
        })
    }
)

/**
 * Bound hash operations for a specific algorithm
 */
export interface BoundHashOps {
    readonly hash: (message: Uint8Array) => Promise<Either<Error, Uint8Array>>
    readonly config: HashConfig
}

/**
 * Create bound hash operations
 * @pure
 */
export const createBoundHashOps = (config: HashConfig): BoundHashOps => ({
    hash: hashMessage(config),
    config
})

/**
 * Helper to create hash operations with error handling
 */
export const createHashOps = (algorithm: HashAlgorithm): Either<Error, BoundHashOps> =>
    createHashConfig(algorithm).map(createBoundHashOps)
