import type { Either } from 'purify-ts'
import type { BoundHashOps } from './hash-functional.js'
import type { BoundKDFOps } from './kdf-functional.js'

/**
 * Create a hash-then-expand pipeline
 * Useful for deriving keys from passwords
 */
export const createHashExpandPipeline = (
    hashOps: BoundHashOps,
    kdfOps: BoundKDFOps,
    info: Uint8Array,
    length: number
) => {
    return async (input: Uint8Array): Promise<Either<Error, Uint8Array>> => {
        // Hash the input
        const hashResult = await hashOps.hash(input)
        if (hashResult.isLeft()) return hashResult

        const hashed = hashResult.unsafeCoerce()

        // Expand to desired length
        return kdfOps.expand(hashed)(info)(length)
    }
}

/**
 * Create extract-expand pipeline with fixed salt
 */
export const createExtractExpandPipeline = (kdfOps: BoundKDFOps, salt: Uint8Array) => {
    return (info: Uint8Array, length: number) => {
        return async (ikm: Uint8Array): Promise<Either<Error, Uint8Array>> => {
            const prk = await kdfOps.extract(salt)(ikm)
            if (prk.isLeft()) return prk

            return kdfOps.expand(prk.unsafeCoerce())(info)(length)
        }
    }
}
