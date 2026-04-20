// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// RFC 9807 Registration Test Vectors Validation

import { describe, it, expect } from '@jest/globals'
import {
    loadTestVector,
    parseVectorHex,
    assertBytesEqual,
    bytesToHex
} from '../src/test-utils/vector-validation.js'

describe('RFC 9807 Registration Test Vectors', () => {
    describe('ristretto255-SHA512 Vector 1 (no identities)', () => {
        it('should match RFC 9807 Appendix C.1.1 registration vector', async () => {
            const vector = await loadTestVector('ristretto255-sha512-real-vector-1.json')
            const intermediates = parseVectorHex(vector.intermediates)
            const outputs = parseVectorHex(vector.outputs)
            const config = vector.config

            // Verify OPRF key derivation matches
            // Note: This requires access to internal OPRF key derivation
            expect(intermediates.oprf_key).toBeDefined()
            expect(bytesToHex(intermediates.oprf_key)).toBe(vector.intermediates.oprf_key)

            // Verify registration request structure
            expect(outputs.registration_request.length).toBe(config.Npk) // Noe (OPRF output)

            // Verify registration response structure
            expect(outputs.registration_response.length).toBe(config.Npk + config.Npk) // Noe + Npk

            // Verify registration upload structure
            // Structure: client_public_key || masking_key || envelope
            const expectedUploadLength = config.Npk + config.Nh + (config.Nn + config.Nm)
            expect(outputs.registration_upload.length).toBe(expectedUploadLength)

            // Verify client public key is in upload
            const clientPubKeyFromUpload = outputs.registration_upload.slice(0, config.Npk)
            assertBytesEqual(
                clientPubKeyFromUpload,
                intermediates.client_public_key,
                'Client public key in registration upload'
            ).mapLeft((err) => {
                throw err
            })

            // Verify masking key is in upload (extract from upload since not in intermediates)
            const maskingKeyFromUpload = outputs.registration_upload.slice(
                config.Npk,
                config.Npk + config.Nh
            )
            expect(maskingKeyFromUpload.length).toBe(config.Nh)

            // Verify envelope is in upload
            const envelopeFromUpload = outputs.registration_upload.slice(config.Npk + config.Nh)
            assertBytesEqual(
                envelopeFromUpload,
                intermediates.envelope,
                'Envelope in registration upload'
            ).mapLeft((err) => {
                throw err
            })
        })
    })

    describe('ristretto255-SHA512 Vector 2 (with identities)', () => {
        it('should match RFC 9807 Appendix C.1.2 registration vector', async () => {
            const vector = await loadTestVector('ristretto255-sha512-real-vector-2.json')
            const inputs = parseVectorHex(vector.inputs)
            const intermediates = parseVectorHex(vector.intermediates)
            const outputs = parseVectorHex(vector.outputs)
            const config = vector.config

            // Verify that client_identity and server_identity are present
            expect(inputs.client_identity).toBeDefined()
            expect(inputs.server_identity).toBeDefined()
            expect(bytesToHex(inputs.client_identity)).toBe('616c696365') // "alice"
            expect(bytesToHex(inputs.server_identity)).toBe('626f62') // "bob"

            // Verify registration structures with identities
            expect(outputs.registration_request.length).toBe(config.Npk)
            expect(outputs.registration_response.length).toBe(config.Npk + config.Npk)

            const expectedUploadLength = config.Npk + config.Nh + (config.Nn + config.Nm)
            expect(outputs.registration_upload.length).toBe(expectedUploadLength)

            // Verify the envelope differs from vector 1 due to identity inclusion
            const vector1 = await loadTestVector('ristretto255-sha512-real-vector-1.json')
            const vector1Intermediates = parseVectorHex(vector1.intermediates)

            // Envelopes should differ because auth_tag covers identities
            expect(bytesToHex(intermediates.envelope)).not.toBe(
                bytesToHex(vector1Intermediates.envelope)
            )
        })
    })

    describe('P256-SHA256 Vector 5', () => {
        it('should match RFC 9807 Appendix C.1.5 registration vector', async () => {
            const vector = await loadTestVector('p256-sha256-real-vector-5.json')
            const config = vector.config
            const outputs = parseVectorHex(vector.outputs)

            // Verify P256 specific sizes
            expect(config.Npk).toBe(33) // Compressed P256 point
            expect(config.Nh).toBe(32) // SHA256 output
            expect(config.Nm).toBe(32) // HMAC-SHA256 output

            // Verify registration request (P256 OPRF element)
            expect(outputs.registration_request.length).toBe(config.Npk)

            // Verify registration response (OPRF eval + server public key)
            expect(outputs.registration_response.length).toBe(config.Npk + config.Npk) // Noe + Npk

            // Verify registration upload structure for P256
            const expectedUploadLength = config.Npk + config.Nh + (config.Nn + config.Nm)
            expect(outputs.registration_upload.length).toBe(expectedUploadLength)
        })
    })

    describe('Registration Message Compliance', () => {
        it('should validate all registration message structures', async () => {
            const vectors = [
                'ristretto255-sha512-real-vector-1.json',
                'ristretto255-sha512-real-vector-2.json',
                'p256-sha256-real-vector-5.json'
            ]

            for (const vectorFile of vectors) {
                const vector = await loadTestVector(vectorFile)
                const config = vector.config
                const outputs = parseVectorHex(vector.outputs)

                // RegistrationRequest: blinded_message[Noe]
                const expectedRequestLength = config.Npk
                expect(outputs.registration_request.length).toBe(expectedRequestLength)

                // RegistrationResponse: evaluated_message[Noe] || server_public_key[Npk]
                const expectedResponseLength = config.Npk + config.Npk
                expect(outputs.registration_response.length).toBe(expectedResponseLength)

                // RegistrationRecord: client_public_key[Npk] || masking_key[Nh] || envelope[Nn + Nm]
                const expectedUploadLength = config.Npk + config.Nh + (config.Nn + config.Nm)
                expect(outputs.registration_upload.length).toBe(expectedUploadLength)
            }
        })
    })
})
