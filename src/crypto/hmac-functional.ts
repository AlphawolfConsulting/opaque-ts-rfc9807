import type { Either } from 'purify-ts'
import { Right, Left } from 'purify-ts'
import { curry2, curry3, tryCatchAsync } from '../functional-utils.js'
import { opaqueLogger } from '../opaque-config.js'
import type { HashAlgorithm } from './hash-functional.js'

/**
 * HMAC configuration
 */
export interface HMACConfig {
    readonly hash: HashAlgorithm
    readonly Nm: number // Output size in bytes
}

/**
 * Create HMAC configuration
 * @pure
 */
export const createHMACConfig = (hash: HashAlgorithm): Either<Error, HMACConfig> => {
    const sizes: Record<HashAlgorithm, number> = {
        'SHA-1': 20,
        'SHA-256': 32,
        'SHA-384': 48,
        'SHA-512': 64
    }

    if (!(hash in sizes)) {
        return Left(new Error(`Invalid hash for HMAC: ${hash}`))
    }

    return Right({
        hash,
        Nm: sizes[hash]
    })
}

/**
 * HMAC operations with key
 */
export interface HMACOps {
    readonly sign: (message: Uint8Array) => Promise<Either<Error, Uint8Array>>
    readonly verify: (message: Uint8Array) => (tag: Uint8Array) => Promise<Either<Error, boolean>>
}

/**
 * Import HMAC key
 *
 * @sideEffect Web Crypto API
 * @sideEffect Logging
 */
const importHMACKey = curry2(
    async (config: HMACConfig, key: Uint8Array): Promise<Either<Error, CryptoKey>> => {
        return tryCatchAsync(async () => {
            opaqueLogger.debug({
                message: 'Importing HMAC key',
                hash: config.hash,
                keyLength: key.length
            })

            // SIDE EFFECT: crypto.subtle.importKey
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                key,
                { name: 'HMAC', hash: config.hash },
                false,
                ['sign', 'verify']
            )

            return cryptoKey
        })
    }
)

/**
 * Sign message with HMAC
 *
 * @sideEffect Web Crypto API
 * @sideEffect Logging
 */
const hmacSign = curry2(
    async (cryptoKey: CryptoKey, message: Uint8Array): Promise<Either<Error, Uint8Array>> => {
        return tryCatchAsync(async () => {
            opaqueLogger.debug({ message: 'Signing with HMAC', messageLength: message.length })

            // SIDE EFFECT: crypto.subtle.sign
            const signature = await crypto.subtle.sign('HMAC', cryptoKey, message)
            const result = new Uint8Array(signature)

            opaqueLogger.debug({
                message: 'HMAC signature generated',
                signatureLength: result.length
            })

            return result
        })
    }
)

/**
 * Verify HMAC tag (constant-time comparison)
 *
 * @sideEffect Logging
 */
const hmacVerify = curry3(
    async (
        cryptoKey: CryptoKey,
        message: Uint8Array,
        tag: Uint8Array
    ): Promise<Either<Error, boolean>> => {
        return tryCatchAsync(async () => {
            opaqueLogger.debug({
                message: 'Verifying HMAC tag',
                messageLength: message.length,
                tagLength: tag.length
            })

            const signResult = await hmacSign(cryptoKey)(message)
            if (signResult.isLeft()) {
                return false
            }

            if (!signResult.isRight()) {
                return false
            }

            const computed = signResult.unsafeCoerce()

            // Constant-time comparison
            if (computed.length !== tag.length) {
                return false
            }

            let diff = 0
            for (let i = 0; i < computed.length; i++) {
                diff |= computed[i] ^ tag[i]
            }

            const valid = diff === 0

            opaqueLogger.debug({ message: 'HMAC verification complete', valid })

            return valid
        })
    }
)

/**
 * Create HMAC operations with key
 *
 * @sideEffect Web Crypto API (key import)
 */
export const createHMACOps = curry2(
    async (config: HMACConfig, key: Uint8Array): Promise<Either<Error, HMACOps>> => {
        const keyResult = await importHMACKey(config)(key)

        if (keyResult.isLeft()) {
            return keyResult
        }

        const cryptoKey = keyResult.unsafeCoerce()

        return Right({
            sign: hmacSign(cryptoKey),
            verify: hmacVerify(cryptoKey)
        })
    }
)

/**
 * Bound HMAC operations
 */
export interface BoundHMACOps {
    readonly withKey: (key: Uint8Array) => Promise<Either<Error, HMACOps>>
    readonly config: HMACConfig
}

/**
 * Create bound HMAC operations
 * @pure
 */
export const createBoundHMACOps = (config: HMACConfig): BoundHMACOps => ({
    withKey: createHMACOps(config),
    config
})

/**
 * Helper to create HMAC operations with error handling
 */
export const createHMAC = (hash: HashAlgorithm): Either<Error, BoundHMACOps> =>
    createHMACConfig(hash).map(createBoundHMACOps)
