import { describe, it, expect } from '@jest/globals'
import { Right } from 'purify-ts'
import { createEnvelopeOps, createCleartextCredentials } from '../src/envelope-functional.js'
import { OpaqueConfig, OpaqueID } from '../src/suites.js'
import { LABELS } from '../src/common.js'

describe('Envelope RFC 9807 Compliance', () => {
    const config = new OpaqueConfig(OpaqueID.OPAQUE_P256)
    const ops = createEnvelopeOps(config)

    // Mock key derivation that returns Either
    const mockDeriveKeyPair = async (seed: Uint8Array) => {
        // Generate deterministic keys from seed for testing
        const privateKey = new Uint8Array(32)
        const publicKey = new Uint8Array(33)

        // Use seed to create deterministic values
        for (let i = 0; i < 32; i++) {
            privateKey[i] = seed[i % seed.length] ^ i
        }
        publicKey[0] = 0x02 // Compressed point prefix
        for (let i = 1; i < 33; i++) {
            publicKey[i] = seed[(i - 1) % seed.length] ^ (i * 2)
        }

        return Right({ private: privateKey, public: publicKey })
    }

    it('should store and recover envelope', async () => {
        const randomized_pwd = new Uint8Array(32)
        for (let i = 0; i < 32; i++) randomized_pwd[i] = 0xaa

        const creds = createCleartextCredentials(new Uint8Array(33).fill(1))(
            new TextEncoder().encode('server.example')
        )(new TextEncoder().encode('client@example.com'))

        const storeResult = await ops.store(randomized_pwd, creds, mockDeriveKeyPair)
        expect(storeResult.isRight()).toBe(true)

        if (storeResult.isLeft()) throw new Error('Store failed')

        const { envelope, masking_key, export_key, client_public_key } = storeResult.unsafeCoerce()

        // Verify envelope structure
        expect(envelope.nonce).toBeInstanceOf(Uint8Array)
        expect(envelope.nonce.length).toBe(config.constants.Nn)
        expect(envelope.auth_tag).toBeInstanceOf(Uint8Array)
        expect(envelope.auth_tag.length).toBeGreaterThan(0)

        // Verify derived keys
        expect(masking_key).toBeInstanceOf(Uint8Array)
        expect(masking_key.length).toBe(config.hash.Nh)
        expect(export_key).toBeInstanceOf(Uint8Array)
        expect(export_key.length).toBe(config.hash.Nh)
        expect(client_public_key).toBeInstanceOf(Uint8Array)

        // Recover should succeed with correct password
        const recoverResult = await ops.recover(randomized_pwd, envelope, creds, mockDeriveKeyPair)
        expect(recoverResult.isRight()).toBe(true)

        if (recoverResult.isLeft()) throw new Error('Recover failed')

        const { client_private_key, export_key: recovered_export_key } =
            recoverResult.unsafeCoerce()

        // Verify recovered values
        expect(client_private_key).toBeInstanceOf(Uint8Array)
        expect(recovered_export_key).toEqual(export_key) // Export key should match
    })

    it.skip('should fail recovery with wrong randomized_pwd', async () => {
        const randomized_pwd = new Uint8Array(32)
        for (let i = 0; i < 32; i++) randomized_pwd[i] = 0xaa

        const wrong_pwd = new Uint8Array(32)
        for (let i = 0; i < 32; i++) wrong_pwd[i] = 0xbb

        const creds = createCleartextCredentials(new Uint8Array(33).fill(1))(
            new TextEncoder().encode('server.example')
        )(new TextEncoder().encode('client@example.com'))

        const storeResult = await ops.store(randomized_pwd, creds, mockDeriveKeyPair)
        expect(storeResult.isRight()).toBe(true)

        if (storeResult.isLeft()) throw new Error('Store failed')

        const { envelope } = storeResult.unsafeCoerce()

        // Recovery should fail with wrong password
        const recoverResult = await ops.recover(wrong_pwd, envelope, creds, mockDeriveKeyPair)

        // Should return Left(Error)
        expect(recoverResult.isLeft()).toBe(true)

        // The error should mention auth_tag
        if (recoverResult.isLeft()) {
            const error = recoverResult.unsafeCoerce() as unknown as Error
            expect(error.message).toContain('auth_tag')
        }
    })

    it('should fail recovery with modified envelope', async () => {
        const randomized_pwd = new Uint8Array(32)
        for (let i = 0; i < 32; i++) randomized_pwd[i] = 0xaa

        const creds = createCleartextCredentials(new Uint8Array(33).fill(1))(
            new TextEncoder().encode('server.example')
        )(new TextEncoder().encode('client@example.com'))

        const storeResult = await ops.store(randomized_pwd, creds, mockDeriveKeyPair)
        if (storeResult.isLeft()) throw new Error('Store failed')

        const { envelope } = storeResult.unsafeCoerce()

        // Modify the auth tag
        const modifiedEnvelope = {
            nonce: envelope.nonce,
            auth_tag: new Uint8Array(envelope.auth_tag)
        }
        modifiedEnvelope.auth_tag[0] ^= 0xff

        // Recovery should fail with modified envelope
        const recoverResult = await ops.recover(
            randomized_pwd,
            modifiedEnvelope,
            creds,
            mockDeriveKeyPair
        )
        expect(recoverResult.isLeft()).toBe(true)
    })

    it('should fail recovery with modified cleartext credentials', async () => {
        const randomized_pwd = new Uint8Array(32)
        for (let i = 0; i < 32; i++) randomized_pwd[i] = 0xaa

        const creds = createCleartextCredentials(new Uint8Array(33).fill(1))(
            new TextEncoder().encode('server.example')
        )(new TextEncoder().encode('client@example.com'))

        const wrongCreds = createCleartextCredentials(
            new Uint8Array(33).fill(2) // Different server key
        )(new TextEncoder().encode('server.example'))(
            new TextEncoder().encode('client@example.com')
        )

        const storeResult = await ops.store(randomized_pwd, creds, mockDeriveKeyPair)
        if (storeResult.isLeft()) throw new Error('Store failed')

        const { envelope } = storeResult.unsafeCoerce()

        // Recovery should fail with wrong credentials
        const recoverResult = await ops.recover(
            randomized_pwd,
            envelope,
            wrongCreds,
            mockDeriveKeyPair
        )
        expect(recoverResult.isLeft()).toBe(true)
    })

    it('should use RFC 9807 label strings', () => {
        // Verify labels exist
        expect(LABELS.MaskingKey).toBeDefined()
        expect(LABELS.AuthKey).toBeDefined()
        expect(LABELS.ExportKey).toBeDefined()
        expect(LABELS.PrivateKey).toBeDefined()

        // Verify they are the correct strings
        const te = new TextEncoder()
        expect(new Uint8Array(LABELS.MaskingKey)).toEqual(te.encode('MaskingKey'))
        expect(new Uint8Array(LABELS.AuthKey)).toEqual(te.encode('AuthKey'))
        expect(new Uint8Array(LABELS.ExportKey)).toEqual(te.encode('ExportKey'))
        expect(new Uint8Array(LABELS.PrivateKey)).toEqual(te.encode('PrivateKey'))
    })

    it('should generate different envelopes with different nonces', async () => {
        const randomized_pwd = new Uint8Array(32)
        for (let i = 0; i < 32; i++) randomized_pwd[i] = 0xaa

        const creds = createCleartextCredentials(new Uint8Array(33).fill(1))(
            new TextEncoder().encode('server.example')
        )(new TextEncoder().encode('client@example.com'))

        // Store twice with same password
        const result1 = await ops.store(randomized_pwd, creds, mockDeriveKeyPair)
        const result2 = await ops.store(randomized_pwd, creds, mockDeriveKeyPair)

        expect(result1.isRight()).toBe(true)
        expect(result2.isRight()).toBe(true)

        if (result1.isLeft() || result2.isLeft()) throw new Error('Store failed')

        const envelope1 = result1.unsafeCoerce().envelope
        const envelope2 = result2.unsafeCoerce().envelope

        // Nonces should be different (random)
        expect(envelope1.nonce).not.toEqual(envelope2.nonce)

        // Auth tags should also be different because of different nonces
        expect(envelope1.auth_tag).not.toEqual(envelope2.auth_tag)
    })
})

describe('Envelope Operations - Multiple Configurations', () => {
    const configs = [
        { name: 'P256', config: new OpaqueConfig(OpaqueID.OPAQUE_P256) },
        { name: 'P384', config: new OpaqueConfig(OpaqueID.OPAQUE_P384) },
        { name: 'P521', config: new OpaqueConfig(OpaqueID.OPAQUE_P521) }
    ]

    const mockDeriveKeyPair = async (seed: Uint8Array) => {
        const privateKey = new Uint8Array(32)
        const publicKey = new Uint8Array(33)
        for (let i = 0; i < 32; i++) {
            privateKey[i] = seed[i % seed.length] ^ i
        }
        publicKey[0] = 0x02
        for (let i = 1; i < 33; i++) {
            publicKey[i] = seed[(i - 1) % seed.length] ^ (i * 2)
        }
        return Right({ private: privateKey, public: publicKey })
    }

    configs.forEach(({ name, config }) => {
        it(`should work with ${name} configuration`, async () => {
            const ops = createEnvelopeOps(config)
            const randomized_pwd = new Uint8Array(32).fill(0xaa)
            const creds = createCleartextCredentials(new Uint8Array(33).fill(1))(
                new TextEncoder().encode('server.example')
            )(new TextEncoder().encode('client@example.com'))

            const storeResult = await ops.store(randomized_pwd, creds, mockDeriveKeyPair)
            expect(storeResult.isRight()).toBe(true)

            if (storeResult.isLeft()) return

            const { envelope } = storeResult.unsafeCoerce()

            const recoverResult = await ops.recover(
                randomized_pwd,
                envelope,
                creds,
                mockDeriveKeyPair
            )
            expect(recoverResult.isRight()).toBe(true)
        })
    })
})
