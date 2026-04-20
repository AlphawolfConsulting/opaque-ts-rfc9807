import type { Either } from 'purify-ts'
import { Right, Left } from 'purify-ts'
import { curry3, curry4, curry5 } from './functional-utils.js'
import { opaqueLogger } from './opaque-config.js'
import { createKDFOps, createHMAC, generateNonce, type HashAlgorithm } from './crypto/index.js'
import { LABELS } from './common.js'
import type { Config } from './config.js'

/**
 * Cleartext credentials structure
 */
export interface CleartextCredentials {
    readonly server_public_key: Uint8Array
    readonly server_identity: Uint8Array
    readonly client_identity: Uint8Array
}

/**
 * Envelope structure (RFC 9807 Section 5.1)
 */
export interface Envelope {
    readonly nonce: Uint8Array // Nn bytes
    readonly auth_tag: Uint8Array // Nm bytes
}

/**
 * Store result from envelope creation
 */
export interface EnvelopeStoreResult {
    readonly envelope: Envelope
    readonly client_public_key: Uint8Array
    readonly masking_key: Uint8Array
    readonly export_key: Uint8Array
}

/**
 * Recover result from envelope recovery
 */
export interface EnvelopeRecoverResult {
    readonly client_private_key: Uint8Array
    readonly export_key: Uint8Array
}

/**
 * Create cleartext credentials
 * @pure
 */
export const createCleartextCredentials = curry3(
    (
        server_public_key: Uint8Array,
        server_identity: Uint8Array,
        client_identity: Uint8Array
    ): CleartextCredentials => ({
        server_public_key,
        server_identity,
        client_identity
    })
)

/**
 * Serialize cleartext credentials for MAC
 * @pure
 */
export const serializeCleartextCreds = (creds: CleartextCredentials): Uint8Array => {
    return new Uint8Array([
        ...creds.server_public_key,
        ...creds.server_identity,
        ...creds.client_identity
    ])
}

/**
 * Store - Create envelope (RFC 9807 Section 5.1)
 *
 * @sideEffect Crypto RNG (nonce generation)
 * @sideEffect Logging
 */
export const storeEnvelope = curry4(
    async (
        config: Config,
        randomized_pwd: Uint8Array,
        cleartextCreds: CleartextCredentials,
        deriveKeyPair: (
            seed: Uint8Array
        ) => Promise<Either<Error, { readonly private: Uint8Array; readonly public: Uint8Array }>>
    ): Promise<Either<Error, EnvelopeStoreResult>> => {
        try {
            opaqueLogger.debug({ message: 'Storing envelope' })

            // SIDE EFFECT: Generate random nonce
            const nonceResult = generateNonce(config.constants.Nn)
            if (nonceResult.isLeft()) throw nonceResult.extract()
            const envelope_nonce = nonceResult.unsafeCoerce()

            // Get KDF operations
            const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
            if (kdfResult.isLeft()) throw kdfResult.extract()
            const kdf = kdfResult.unsafeCoerce()

            // Derive keys using HKDF-Expand with labels (RFC 9807 Section 5.1)
            const expandWithPwd = kdf.expand(randomized_pwd)

            // masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
            const maskingKeyResult = await expandWithPwd(new Uint8Array(LABELS.MaskingKey))(
                config.hash.Nh
            )
            if (maskingKeyResult.isLeft()) throw maskingKeyResult.extract()
            const masking_key = maskingKeyResult.unsafeCoerce()

            // auth_key = Expand(randomized_pwd, concat(nonce, "AuthKey"), Nh)
            const authKeyInfo = new Uint8Array([...envelope_nonce, ...LABELS.AuthKey])
            const authKeyResult = await expandWithPwd(authKeyInfo)(config.hash.Nh)
            if (authKeyResult.isLeft()) throw authKeyResult.extract()
            const auth_key = authKeyResult.unsafeCoerce()

            // export_key = Expand(randomized_pwd, concat(nonce, "ExportKey"), Nh)
            const exportKeyInfo = new Uint8Array([
                ...envelope_nonce,
                ...new Uint8Array(LABELS.ExportKey)
            ])
            const exportKeyResult = await expandWithPwd(exportKeyInfo)(config.hash.Nh)
            if (exportKeyResult.isLeft()) throw exportKeyResult.extract()
            const export_key = exportKeyResult.unsafeCoerce()

            // seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nseed)
            const seedInfo = new Uint8Array([...envelope_nonce, ...LABELS.PrivateKey])
            const seedResult = await expandWithPwd(seedInfo)(config.constants.Nseed)
            if (seedResult.isLeft()) throw seedResult.extract()
            const seed = seedResult.unsafeCoerce()

            // Derive client key pair
            const keyPairResult = await deriveKeyPair(seed)
            if (keyPairResult.isLeft()) throw keyPairResult.extract()
            const { private: _client_private_key, public: client_public_key } =
                keyPairResult.unsafeCoerce()

            // Compute auth_tag = MAC(auth_key, concat(nonce, cleartext_creds))
            const hmacResult = createHMAC(config.hash.name as HashAlgorithm)
            if (hmacResult.isLeft()) throw hmacResult.extract()

            const hmacOpsResult = await hmacResult.unsafeCoerce().withKey(auth_key)
            if (hmacOpsResult.isLeft()) throw hmacOpsResult.extract()
            const hmacOps = hmacOpsResult.unsafeCoerce()

            const cleartextSerialized = serializeCleartextCreds(cleartextCreds)
            const macInput = new Uint8Array([...envelope_nonce, ...cleartextSerialized])
            const authTagResult = await hmacOps.sign(macInput)
            if (authTagResult.isLeft()) throw authTagResult.extract()
            const auth_tag = authTagResult.unsafeCoerce()

            const envelope: Envelope = {
                nonce: envelope_nonce,
                auth_tag
            }

            opaqueLogger.debug({ message: 'Envelope stored' })

            return Right({
                envelope,
                client_public_key,
                masking_key,
                export_key
            })
        } catch (e) {
            return Left(e as Error)
        }
    }
)

/**
 * Recover - Recover credentials from envelope (RFC 9807 Section 5.1)
 *
 * @sideEffect Logging
 */
export const recoverEnvelope = curry5(
    async (
        config: Config,
        randomized_pwd: Uint8Array,
        envelope: Envelope,
        cleartextCreds: CleartextCredentials,
        deriveKeyPair: (
            seed: Uint8Array
        ) => Promise<Either<Error, { readonly private: Uint8Array; readonly public: Uint8Array }>>
    ): Promise<Either<Error, EnvelopeRecoverResult>> => {
        try {
            opaqueLogger.debug({ message: 'Recovering envelope' })

            // Get KDF operations
            const kdfResult = createKDFOps(config.hash.name as HashAlgorithm)
            if (kdfResult.isLeft()) throw kdfResult.extract()
            const kdf = kdfResult.unsafeCoerce()

            const expandWithPwd = kdf.expand(randomized_pwd)

            // Re-derive keys using same process as Store
            const authKeyInfo = new Uint8Array([...envelope.nonce, ...LABELS.AuthKey])
            const authKeyResult = await expandWithPwd(authKeyInfo)(config.hash.Nh)
            if (authKeyResult.isLeft()) throw authKeyResult.extract()
            const auth_key = authKeyResult.unsafeCoerce()

            const exportKeyInfo = new Uint8Array([...envelope.nonce, ...LABELS.ExportKey])
            const exportKeyResult = await expandWithPwd(exportKeyInfo)(config.hash.Nh)
            if (exportKeyResult.isLeft()) throw exportKeyResult.extract()
            const export_key = exportKeyResult.unsafeCoerce()

            const seedInfo = new Uint8Array([...envelope.nonce, ...LABELS.PrivateKey])
            const seedResult = await expandWithPwd(seedInfo)(config.constants.Nseed)
            if (seedResult.isLeft()) throw seedResult.extract()
            const seed = seedResult.unsafeCoerce()

            // Derive client key pair
            const keyPairResult = await deriveKeyPair(seed)
            if (keyPairResult.isLeft()) throw keyPairResult.extract()
            const { private: client_private_key } = keyPairResult.unsafeCoerce()

            // Verify auth_tag
            const hmacResult = createHMAC(config.hash.name as HashAlgorithm)
            if (hmacResult.isLeft()) throw hmacResult.extract()

            const hmacOpsResult = await hmacResult.unsafeCoerce().withKey(auth_key)
            if (hmacOpsResult.isLeft()) throw hmacOpsResult.extract()
            const hmacOps = hmacOpsResult.unsafeCoerce()

            const cleartextSerialized = serializeCleartextCreds(cleartextCreds)
            const macInput = new Uint8Array([...envelope.nonce, ...cleartextSerialized])
            const validResult = await hmacOps.verify(macInput)(envelope.auth_tag)
            if (validResult.isLeft()) throw validResult.extract()

            if (!validResult.unsafeCoerce()) {
                throw new Error('Envelope authentication failed: Invalid auth_tag')
            }

            opaqueLogger.debug({ message: 'Envelope recovered successfully' })

            return Right({
                client_private_key,
                export_key
            })
        } catch (e) {
            opaqueLogger.debug({ message: 'Error in recoverEnvelope', error: String(e) })
            return Left(e as Error)
        }
    }
)

/**
 * Bound envelope operations
 */
export interface BoundEnvelopeOps {
    readonly store: (
        randomized_pwd: Uint8Array,
        cleartextCreds: CleartextCredentials,
        deriveKeyPair: (
            seed: Uint8Array
        ) => Promise<Either<Error, { readonly private: Uint8Array; readonly public: Uint8Array }>>
    ) => Promise<Either<Error, EnvelopeStoreResult>>

    readonly recover: (
        randomized_pwd: Uint8Array,
        envelope: Envelope,
        cleartextCreds: CleartextCredentials,
        deriveKeyPair: (
            seed: Uint8Array
        ) => Promise<Either<Error, { readonly private: Uint8Array; readonly public: Uint8Array }>>
    ) => Promise<Either<Error, EnvelopeRecoverResult>>
}

/**
 * Create bound envelope operations for a configuration
 * @pure
 */
export const createEnvelopeOps = (config: Config): BoundEnvelopeOps => ({
    store: (randomized_pwd, cleartextCreds, deriveKeyPair) =>
        storeEnvelope(config)(randomized_pwd)(cleartextCreds)(deriveKeyPair),
    recover: (randomized_pwd, envelope, cleartextCreds, deriveKeyPair) =>
        recoverEnvelope(config)(randomized_pwd)(envelope)(cleartextCreds)(deriveKeyPair)
})
