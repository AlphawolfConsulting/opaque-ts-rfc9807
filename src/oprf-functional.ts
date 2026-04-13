// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// Functional OPRF wrapper with RFC 9497 compliance

import { Either, Right, Left } from 'purify-ts'
import { curry2, curry3, tryCatchAsync } from './functional-utils.js'
import { opaqueLogger } from './opaque-config.js'
import type { SuiteID } from '@cloudflare/voprf-ts'
import {
    OPRFClient,
    OPRFServer,
    Oprf,
    EvaluationRequest,
    FinalizeData,
    Evaluation,
    deriveKeyPair
} from '@cloudflare/voprf-ts'
import { LABELS } from './common.js'

/**
 * OPRF Configuration with RFC 9497 compliance
 */
export interface OPRFConfig {
    readonly suiteId: SuiteID
    readonly mode: number // 0x00 for modeOPRF (base mode)
    readonly Noe: number // Size of serialized OPRF group element
    readonly hash: string // Hash function name
    readonly groupName: string // Group identifier
}

/**
 * Create immutable OPRF configuration
 * @pure
 */
export const createOPRFConfig = (suiteId: SuiteID): Either<Error, OPRFConfig> => {
    try {
        const group = Oprf.getGroup(suiteId)
        const hash = Oprf.getHash(suiteId)

        const config: OPRFConfig = {
            suiteId,
            mode: 0x00, // RFC 9497 modeOPRF (base mode)
            Noe: group.eltSize(true),
            hash,
            groupName: group.id
        }

        opaqueLogger.debug({ message: `Created OPRF config for suite ${suiteId}` })
        return Right(config)
    } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error))
        opaqueLogger.error({ message: `Failed to create OPRF config: ${err.message}` })
        return Left(err)
    }
}

/**
 * OPRF Blind Operation Result
 */
export interface BlindResult {
    readonly blind: Uint8Array
    readonly blindedElement: Uint8Array
}

/**
 * Blind password input (Client-side OPRF operation)
 *
 * @sideEffect Crypto RNG (via OPRFClient)
 * @sideEffect Logging
 * @param config OPRF configuration
 * @param input Password as bytes
 * @returns Either<Error, BlindResult>
 */
export const blindPassword = curry2(
    async (config: OPRFConfig, input: Uint8Array): Promise<Either<Error, BlindResult>> => {
        return tryCatchAsync(async () => {
            opaqueLogger.debug({ message: `Blinding password for suite ${config.suiteId}` })

            // SIDE EFFECT: OPRFClient uses crypto RNG
            const client = new OPRFClient(config.suiteId)
            const [finData, evalReq] = await client.blind([input])

            const result: BlindResult = {
                blind: finData.blinds[0].serialize(),
                blindedElement: evalReq.blinded[0].serialize()
            }

            opaqueLogger.debug({ message: `Password blinded successfully (${result.blindedElement.length} bytes)` })

            return result
        })
    }
)

/**
 * Evaluate blinded element (Server-side OPRF operation)
 *
 * @sideEffect Logging
 * @param config OPRF configuration
 * @param oprfKey Server OPRF private key
 * @param blindedElement Blinded password element from client
 * @returns Either<Error, Uint8Array> Evaluation result
 */
export const evaluateBlinded = curry3(
    async (
        config: OPRFConfig,
        oprfKey: Uint8Array,
        blindedElement: Uint8Array
    ): Promise<Either<Error, Uint8Array>> => {
        return tryCatchAsync(async () => {
            opaqueLogger.debug({ message: `Evaluating blinded element for suite ${config.suiteId}` })

            const server = new OPRFServer(config.suiteId, oprfKey)
            const group = Oprf.getGroup(config.suiteId)
            const deserBlinded = group.desElt(blindedElement)
            const evalReq = new EvaluationRequest([deserBlinded])
            const evaluations = await server.blindEvaluate(evalReq)

            const evaluation = evaluations.evaluated[0].serialize()

            opaqueLogger.debug({ message: `Evaluation complete (${evaluation.length} bytes)` })

            return evaluation
        })
    }
)

/**
 * Finalize OPRF to get output (Client-side)
 *
 * @sideEffect Logging
 * @param config OPRF configuration
 * @param input Original password input
 * @param blind Blind value from blind operation
 * @param evaluation Evaluation from server
 * @returns Either<Error, Uint8Array> Final OPRF output
 */
export const finalizeOPRF = curry2(
    async (
        config: OPRFConfig,
        params: { input: Uint8Array; blind: Uint8Array; evaluation: Uint8Array }
    ): Promise<Either<Error, Uint8Array>> => {
        const { input, blind, evaluation } = params
        return tryCatchAsync(async () => {
            opaqueLogger.debug({ message: `Finalizing OPRF for suite ${config.suiteId}` })

            const client = new OPRFClient(config.suiteId)
            const group = Oprf.getGroup(config.suiteId)
            const deserEval = group.desElt(evaluation)
            const blindSc = group.desScalar(blind)
            const finData = new FinalizeData([input], [blindSc], new EvaluationRequest([]))
            const evalObj = new Evaluation(client.mode, [deserEval])

            const outputs = await client.finalize(finData, evalObj)
            const output = outputs[0]

            opaqueLogger.debug({ message: `OPRF finalized (${output.length} bytes)` })

            return output
        })
    }
)

/**
 * Derive OPRF key pair from seed (RFC 9497 compliant)
 *
 * @sideEffect Logging
 * @param config OPRF configuration
 * @param seed Random seed for key derivation
 * @returns Either<Error, Uint8Array> Private key
 */
export const deriveOPRFKeyPair = curry2(
    async (config: OPRFConfig, seed: Uint8Array): Promise<Either<Error, Uint8Array>> => {
        return tryCatchAsync(async () => {
            opaqueLogger.debug({ message: `Deriving OPRF key pair for suite ${config.suiteId}` })

            const keyPair = await deriveKeyPair(
                Oprf.Mode.OPRF,
                config.suiteId,
                seed,
                Uint8Array.from(LABELS.OPAQUE_DeriveKeyPair)
            )
            const privateKey = keyPair.privateKey

            opaqueLogger.debug({ message: `OPRF key pair derived (${privateKey.length} bytes)` })

            return privateKey
        })
    }
)

/**
 * Curried OPRF operations bound to configuration
 * This allows partial application of config for cleaner code
 */
export interface BoundOPRFOperations {
    blind: (input: Uint8Array) => Promise<Either<Error, BlindResult>>
    evaluate: (
        oprfKey: Uint8Array
    ) => (blindedElement: Uint8Array) => Promise<Either<Error, Uint8Array>>
    finalize: (params: {
        input: Uint8Array
        blind: Uint8Array
        evaluation: Uint8Array
    }) => Promise<Either<Error, Uint8Array>>
    deriveKeyPair: (seed: Uint8Array) => Promise<Either<Error, Uint8Array>>
}

/**
 * Create OPRF operations bound to a specific configuration
 *
 * @pure (returns pure functions with side effects isolated)
 * @param config OPRF configuration
 * @returns Bound OPRF operations
 */
export const createBoundOPRFOps = (config: OPRFConfig): BoundOPRFOperations => ({
    blind: blindPassword(config),
    evaluate: evaluateBlinded(config),
    finalize: finalizeOPRF(config),
    deriveKeyPair: deriveOPRFKeyPair(config)
})

/**
 * Helper to create OPRF operations with error handling
 *
 * @param suiteId OPRF suite identifier
 * @returns Either<Error, BoundOPRFOperations>
 */
export const createOPRFOps = (suiteId: SuiteID): Either<Error, BoundOPRFOperations> =>
    createOPRFConfig(suiteId).map(createBoundOPRFOps)
