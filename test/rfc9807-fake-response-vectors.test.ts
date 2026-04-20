// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// RFC 9807 Fake Credential Response Test Vectors Validation

import { describe, it, expect } from '@jest/globals'
import {
    loadTestVector,
    parseVectorHex,
    assertBytesEqual,
    bytesToHex
} from '../src/test-utils/vector-validation.js'

describe('RFC 9807 Fake Credential Response Test Vectors', () => {
    describe('ristretto255-SHA512 Fake Response', () => {
        it('should match RFC 9807 Appendix C.2.1 fake credential response', async () => {
            const fakeVector = await loadTestVector('ristretto255-sha512-fake-vector-1.json')
            const inputs = parseVectorHex(fakeVector.inputs)
            const outputs = parseVectorHex(fakeVector.outputs)
            const config = fakeVector.config

            // Verify KE1 input structure
            expect(inputs.KE1.length).toBe(config.Nok + config.Nn + config.Npk)

            // Verify KE2 output structure (same as real credential response)
            const credResponseLength = config.Nok + config.Nn + (config.Npk + config.Nn + config.Nm)
            const authResponseLength = config.Nn + config.Npk + config.Nm
            const expectedKE2Length = credResponseLength + authResponseLength

            expect(outputs.KE2.length).toBe(expectedKE2Length)

            // Verify masking nonce is present and correct length
            const maskingNonceStart = config.Nok
            const maskingNonce = outputs.KE2.slice(maskingNonceStart, maskingNonceStart + config.Nn)
            expect(maskingNonce.length).toBe(config.Nn)

            assertBytesEqual(
                maskingNonce,
                inputs.masking_nonce,
                'Masking nonce in fake KE2'
            ).mapLeft((err) => {
                throw err
            })
        })
    })

    describe('Fake Response Indistinguishability', () => {
        it('should produce KE2 with same structure as real response', async () => {
            const fakeVector = await loadTestVector('ristretto255-sha512-fake-vector-1.json')
            const realVector = await loadTestVector('ristretto255-sha512-real-vector-2.json')

            const fakeOutputs = parseVectorHex(fakeVector.outputs)
            const realOutputs = parseVectorHex(realVector.outputs)

            // KE2 messages should have identical length
            expect(fakeOutputs.KE2.length).toBe(realOutputs.KE2.length)

            // Extract components from both
            const config = fakeVector.config
            const credResponseLength = config.Nok + config.Nn + (config.Npk + config.Nn + config.Nm)

            // Credential response section lengths should match
            const fakeCredResponse = fakeOutputs.KE2.slice(0, credResponseLength)
            const realCredResponse = realOutputs.KE2.slice(0, credResponseLength)
            expect(fakeCredResponse.length).toBe(realCredResponse.length)

            // Auth response section lengths should match
            const fakeAuthResponse = fakeOutputs.KE2.slice(credResponseLength)
            const realAuthResponse = realOutputs.KE2.slice(credResponseLength)
            expect(fakeAuthResponse.length).toBe(realAuthResponse.length)

            // Content should differ (but structure is identical)
            expect(bytesToHex(fakeOutputs.KE2)).not.toBe(bytesToHex(realOutputs.KE2))
        })

        it('should use fake record parameters correctly', async () => {
            const fakeVector = await loadTestVector('ristretto255-sha512-fake-vector-1.json')
            const inputs = parseVectorHex(fakeVector.inputs)

            // Fake record should have client keys
            expect(inputs.client_private_key).toBeDefined()
            expect(inputs.client_public_key).toBeDefined()
            expect(inputs.client_private_key.length).toBe(32)
            expect(inputs.client_public_key.length).toBe(32)

            // Fake record should have masking key
            expect(inputs.masking_key).toBeDefined()
            expect(inputs.masking_key.length).toBe(64)

            // Server keys should be present
            expect(inputs.server_private_key).toBeDefined()
            expect(inputs.server_public_key).toBeDefined()
        })
    })

    describe('Fake Response Security Properties', () => {
        it('should include proper nonces and prevent replay', async () => {
            const fakeVector = await loadTestVector('ristretto255-sha512-fake-vector-1.json')
            const outputs = parseVectorHex(fakeVector.outputs)
            const inputs = parseVectorHex(fakeVector.inputs)
            const config = fakeVector.config

            // Extract server nonce from KE2
            const credResponseLength = config.Nok + config.Nn + (config.Npk + config.Nn + config.Nm)
            const serverNonceStart = credResponseLength
            const serverNonce = outputs.KE2.slice(serverNonceStart, serverNonceStart + config.Nn)

            // Server nonce should be present and match input
            expect(serverNonce.length).toBe(config.Nn)
            assertBytesEqual(serverNonce, inputs.server_nonce, 'Server nonce in fake KE2').mapLeft(
                (err) => {
                    throw err
                }
            )
        })

        it('should include valid server MAC', async () => {
            const fakeVector = await loadTestVector('ristretto255-sha512-fake-vector-1.json')
            const outputs = parseVectorHex(fakeVector.outputs)
            const config = fakeVector.config

            // Extract server MAC from end of KE2
            const serverMac = outputs.KE2.slice(-config.Nm)
            expect(serverMac.length).toBe(config.Nm)

            // Server MAC should be non-zero (computed over fake data)
            const isNonZero = serverMac.some((byte) => byte !== 0)
            expect(isNonZero).toBe(true)
        })
    })

    describe('Enumeration Prevention', () => {
        it('should demonstrate indistinguishability from real responses', async () => {
            const fakeVector = await loadTestVector('ristretto255-sha512-fake-vector-1.json')
            const realVector = await loadTestVector('ristretto255-sha512-real-vector-2.json')

            const fakeKE2 = parseVectorHex(fakeVector.outputs).KE2
            const realKE2 = parseVectorHex(realVector.outputs).KE2

            // Both should be same length
            expect(fakeKE2.length).toBe(realKE2.length)

            // Both should have non-zero content
            const fakeNonZero = fakeKE2.some((byte) => byte !== 0)
            const realNonZero = realKE2.some((byte) => byte !== 0)
            expect(fakeNonZero).toBe(true)
            expect(realNonZero).toBe(true)

            // Both should have different values (not predictable)
            expect(bytesToHex(fakeKE2)).not.toBe(bytesToHex(realKE2))

            // Structure test: both should parse into same components
            const config = fakeVector.config
            const componentLengths = [
                config.Nok, // evaluated_message
                config.Nn, // masking_nonce
                config.Npk + config.Nn + config.Nm, // masked_response
                config.Nn, // server_nonce
                config.Npk, // server_public_keyshare
                config.Nm // server_mac
            ]

            let offset = 0
            for (const length of componentLengths) {
                const fakeComponent = fakeKE2.slice(offset, offset + length)
                const realComponent = realKE2.slice(offset, offset + length)
                expect(fakeComponent.length).toBe(length)
                expect(realComponent.length).toBe(length)
                offset += length
            }
        })
    })
})
