import { describe, it, expect } from '@jest/globals'
import { Right } from 'purify-ts'
import { createRegistrationOps } from '../src/registration-functional.js'
import { OpaqueConfig, OpaqueID } from '../src/suites.js'
import { IdentityKSFFn } from '../src/thecrypto.js'

describe('Registration RFC 9807 Compliance', () => {
    const config = new OpaqueConfig(OpaqueID.OPAQUE_P256)
    const ops = createRegistrationOps(config)

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

    describe('CreateRegistrationRequest', () => {
        it('should create a valid registration request', async () => {
            const password = new TextEncoder().encode('correct horse battery staple')

            const result = await ops.createRequest(password)

            expect(result.isRight()).toBe(true)

            if (result.isLeft()) throw new Error('Request creation failed')

            const { request, blind, requestId } = result.unsafeCoerce()

            // Verify request structure (RFC 9807 Section 5.1)
            expect(request.data).toBeInstanceOf(Uint8Array)
            expect(request.data.length).toBeGreaterThan(0)

            // Verify blind
            expect(blind).toBeInstanceOf(Uint8Array)
            expect(blind.length).toBeGreaterThan(0)

            // Verify tracking ID
            expect(typeof requestId).toBe('string')
            expect(requestId.length).toBeGreaterThan(0)
        })

        it('should create different blinded elements for same password', async () => {
            const password = new TextEncoder().encode('same password')

            const result1 = await ops.createRequest(password)
            const result2 = await ops.createRequest(password)

            expect(result1.isRight()).toBe(true)
            expect(result2.isRight()).toBe(true)

            if (result1.isLeft() || result2.isLeft()) {
                throw new Error('Request creation failed')
            }

            const request1 = result1.unsafeCoerce()
            const request2 = result2.unsafeCoerce()

            // Blind and blinded elements should be different (due to RNG)
            expect(request1.blind).not.toEqual(request2.blind)
            expect(request1.request.data).not.toEqual(request2.request.data)
        })
    })

    describe('CreateRegistrationResponse', () => {
        it('should create a valid registration response', async () => {
            const password = new TextEncoder().encode('test password')

            // Step 1: Create request (client)
            const requestResult = await ops.createRequest(password)
            expect(requestResult.isRight()).toBe(true)

            if (requestResult.isLeft()) throw new Error('Request creation failed')

            const { request } = requestResult.unsafeCoerce()

            // Step 2: Create response (server)
            const server_public_key = new Uint8Array(33).fill(0x02)
            const oprf_seed = new Uint8Array(32).fill(0xaa)

            const responseResult = await ops.createResponse(request, server_public_key, oprf_seed)

            expect(responseResult.isRight()).toBe(true)

            if (responseResult.isLeft()) throw new Error('Response creation failed')

            const response = responseResult.unsafeCoerce()

            // Verify response structure (RFC 9807 Section 5.1)
            expect(response.data).toBeInstanceOf(Uint8Array)
            expect(response.data.length).toBeGreaterThan(0)
            expect(response.server_public_key).toEqual(server_public_key)
        })

        it('should produce deterministic evaluation with same seed', async () => {
            const password = new TextEncoder().encode('test password')

            const requestResult = await ops.createRequest(password)
            expect(requestResult.isRight()).toBe(true)

            if (requestResult.isLeft()) throw new Error('Request creation failed')

            const { request } = requestResult.unsafeCoerce()

            const server_public_key = new Uint8Array(33).fill(0x02)
            const oprf_seed = new Uint8Array(32).fill(0xbb)

            const response1 = await ops.createResponse(request, server_public_key, oprf_seed)
            const response2 = await ops.createResponse(request, server_public_key, oprf_seed)

            expect(response1.isRight()).toBe(true)
            expect(response2.isRight()).toBe(true)

            if (response1.isLeft() || response2.isLeft()) {
                throw new Error('Response creation failed')
            }

            // Same seed should produce same evaluation
            expect(response1.unsafeCoerce().data).toEqual(response2.unsafeCoerce().data)
        })
    })

    describe('FinalizeRegistrationRequest', () => {
        it('should finalize registration with Identity KSF', async () => {
            const password = new TextEncoder().encode('test password')
            const server_identity = new TextEncoder().encode('server.example')
            const client_identity = new TextEncoder().encode('client@example.com')

            // Step 1: Create request (client)
            const requestResult = await ops.createRequest(password)
            expect(requestResult.isRight()).toBe(true)

            if (requestResult.isLeft()) throw new Error('Request creation failed')

            const { request, blind } = requestResult.unsafeCoerce()

            // Step 2: Create response (server)
            const server_public_key = new Uint8Array(33).fill(0x02)
            const oprf_seed = new Uint8Array(32).fill(0xaa)

            const responseResult = await ops.createResponse(request, server_public_key, oprf_seed)

            expect(responseResult.isRight()).toBe(true)

            if (responseResult.isLeft()) throw new Error('Response creation failed')

            const response = responseResult.unsafeCoerce()

            // Step 3: Finalize request (client)
            const finalizeResult = await ops.finalizeRequest(
                password,
                blind,
                response,
                server_identity,
                client_identity,
                IdentityKSFFn,
                mockDeriveKeyPair
            )

            expect(finalizeResult.isRight()).toBe(true)

            if (finalizeResult.isLeft()) throw new Error('Finalize failed')

            const { record, export_key, recordId } = finalizeResult.unsafeCoerce()

            // Verify record structure (RFC 9807 Section 5.1)
            expect(record.client_public_key).toBeInstanceOf(Uint8Array)
            expect(record.client_public_key.length).toBeGreaterThan(0)

            expect(record.masking_key).toBeInstanceOf(Uint8Array)
            expect(record.masking_key.length).toBe(config.hash.Nh)

            expect(record.envelope.nonce).toBeInstanceOf(Uint8Array)
            expect(record.envelope.nonce.length).toBe(config.constants.Nn)

            expect(record.envelope.auth_tag).toBeInstanceOf(Uint8Array)
            expect(record.envelope.auth_tag.length).toBeGreaterThan(0)

            // Verify export key
            expect(export_key).toBeInstanceOf(Uint8Array)
            expect(export_key.length).toBe(config.hash.Nh)

            // Verify tracking ID
            expect(typeof recordId).toBe('string')
            expect(recordId.length).toBeGreaterThan(0)
        })

        it('should complete full registration round-trip', async () => {
            const password = new TextEncoder().encode('my secure password')
            const server_identity = new TextEncoder().encode('server.example')
            const client_identity = new TextEncoder().encode('alice@example.com')

            // CLIENT: Step 1 - Create registration request
            const requestResult = await ops.createRequest(password)
            expect(requestResult.isRight()).toBe(true)

            if (requestResult.isLeft()) throw new Error('Request failed')

            const { request, blind } = requestResult.unsafeCoerce()

            // SERVER: Step 2 - Create registration response
            const server_public_key = new Uint8Array(33).fill(0x03)
            const oprf_seed = new Uint8Array(32).fill(0xcc)

            const responseResult = await ops.createResponse(request, server_public_key, oprf_seed)

            expect(responseResult.isRight()).toBe(true)

            if (responseResult.isLeft()) throw new Error('Response failed')

            const response = responseResult.unsafeCoerce()

            // CLIENT: Step 3 - Finalize registration
            const finalizeResult = await ops.finalizeRequest(
                password,
                blind,
                response,
                server_identity,
                client_identity,
                IdentityKSFFn,
                mockDeriveKeyPair
            )

            expect(finalizeResult.isRight()).toBe(true)

            if (finalizeResult.isLeft()) throw new Error('Finalize failed')

            const { record } = finalizeResult.unsafeCoerce()

            // Verify complete registration record
            expect(record).toBeDefined()
            expect(record.client_public_key.length).toBeGreaterThan(0)
            expect(record.masking_key.length).toBe(config.hash.Nh)
            expect(record.envelope.nonce.length).toBe(config.constants.Nn)
            expect(record.envelope.auth_tag.length).toBeGreaterThan(0)
        })
    })

    describe('Multiple Configurations', () => {
        const configs = [
            { id: OpaqueID.OPAQUE_P256, name: 'P256' },
            { id: OpaqueID.OPAQUE_P384, name: 'P384' },
            { id: OpaqueID.OPAQUE_P521, name: 'P521' }
        ]

        configs.forEach(({ id, name }) => {
            it(`should complete registration with ${name} configuration`, async () => {
                const config = new OpaqueConfig(id)
                const ops = createRegistrationOps(config)

                const password = new TextEncoder().encode('test password')
                const server_identity = new TextEncoder().encode('server.example')
                const client_identity = new TextEncoder().encode('client@example.com')

                // Step 1: Request
                const requestResult = await ops.createRequest(password)
                expect(requestResult.isRight()).toBe(true)

                if (requestResult.isLeft()) throw new Error(`${name} request failed`)

                const { request, blind } = requestResult.unsafeCoerce()

                // Step 2: Response
                const server_public_key = new Uint8Array(config.ake.Npk).fill(0x02)
                const oprf_seed = new Uint8Array(32).fill(0xdd)

                const responseResult = await ops.createResponse(
                    request,
                    server_public_key,
                    oprf_seed
                )

                expect(responseResult.isRight()).toBe(true)

                if (responseResult.isLeft()) throw new Error(`${name} response failed`)

                const response = responseResult.unsafeCoerce()

                // Step 3: Finalize
                const finalizeResult = await ops.finalizeRequest(
                    password,
                    blind,
                    response,
                    server_identity,
                    client_identity,
                    IdentityKSFFn,
                    mockDeriveKeyPair
                )

                expect(finalizeResult.isRight()).toBe(true)

                if (finalizeResult.isLeft()) throw new Error(`${name} finalize failed`)

                const { record } = finalizeResult.unsafeCoerce()

                // Verify record for this configuration
                expect(record.masking_key.length).toBe(config.hash.Nh)
                expect(record.envelope.nonce.length).toBe(config.constants.Nn)
            })
        })
    })

    describe('RFC 9807 Message Structures', () => {
        it('should have correct RegistrationRequest structure', async () => {
            const password = new TextEncoder().encode('test')

            const result = await ops.createRequest(password)
            expect(result.isRight()).toBe(true)

            if (result.isLeft()) throw new Error('Failed')

            const { request } = result.unsafeCoerce()

            // RFC 9807 Section 5.1: RegistrationRequest
            // struct { uint8 data[Noe]; }
            expect(request).toHaveProperty('data')
            expect(request.data).toBeInstanceOf(Uint8Array)
            expect(request.data.length).toBe(config.oprf.Noe)
        })

        it('should have correct RegistrationResponse structure', async () => {
            const password = new TextEncoder().encode('test')

            const requestResult = await ops.createRequest(password)
            expect(requestResult.isRight()).toBe(true)

            if (requestResult.isLeft()) throw new Error('Request failed')

            const { request } = requestResult.unsafeCoerce()

            const server_public_key = new Uint8Array(config.ake.Npk).fill(0x02)
            const oprf_seed = new Uint8Array(32).fill(0xee)

            const responseResult = await ops.createResponse(request, server_public_key, oprf_seed)

            expect(responseResult.isRight()).toBe(true)

            if (responseResult.isLeft()) throw new Error('Response failed')

            const response = responseResult.unsafeCoerce()

            // RFC 9807 Section 5.1: RegistrationResponse
            // struct { uint8 data[Noe]; uint8 server_public_key[Npk]; }
            expect(response).toHaveProperty('data')
            expect(response).toHaveProperty('server_public_key')
            expect(response.data).toBeInstanceOf(Uint8Array)
            expect(response.data.length).toBe(config.oprf.Noe)
            expect(response.server_public_key).toBeInstanceOf(Uint8Array)
            expect(response.server_public_key.length).toBe(config.ake.Npk)
        })

        it('should have correct RegistrationRecord structure', async () => {
            const password = new TextEncoder().encode('test')
            const server_identity = new TextEncoder().encode('server')
            const client_identity = new TextEncoder().encode('client')

            const requestResult = await ops.createRequest(password)
            if (requestResult.isLeft()) throw new Error('Request failed')

            const { request, blind } = requestResult.unsafeCoerce()

            const server_public_key = new Uint8Array(config.ake.Npk).fill(0x02)
            const oprf_seed = new Uint8Array(32).fill(0xff)

            const responseResult = await ops.createResponse(request, server_public_key, oprf_seed)
            if (responseResult.isLeft()) throw new Error('Response failed')

            const response = responseResult.unsafeCoerce()

            const finalizeResult = await ops.finalizeRequest(
                password,
                blind,
                response,
                server_identity,
                client_identity,
                IdentityKSFFn,
                mockDeriveKeyPair
            )

            expect(finalizeResult.isRight()).toBe(true)

            if (finalizeResult.isLeft()) throw new Error('Finalize failed')

            const { record } = finalizeResult.unsafeCoerce()

            // RFC 9807 Section 5.1: RegistrationRecord
            // struct {
            //   uint8 client_public_key[Npk];
            //   uint8 masking_key[Nh];
            //   Envelope envelope;
            // }
            expect(record).toHaveProperty('client_public_key')
            expect(record).toHaveProperty('masking_key')
            expect(record).toHaveProperty('envelope')

            expect(record.client_public_key).toBeInstanceOf(Uint8Array)
            expect(record.client_public_key.length).toBe(config.ake.Npk)

            expect(record.masking_key).toBeInstanceOf(Uint8Array)
            expect(record.masking_key.length).toBe(config.hash.Nh)

            expect(record.envelope).toHaveProperty('nonce')
            expect(record.envelope).toHaveProperty('auth_tag')
            expect(record.envelope.nonce).toBeInstanceOf(Uint8Array)
            expect(record.envelope.auth_tag).toBeInstanceOf(Uint8Array)
        })
    })
})
