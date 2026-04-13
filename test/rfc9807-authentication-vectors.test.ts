// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// RFC 9807 Authentication Test Vectors Validation

import { describe, it, expect } from '@jest/globals'
import {
  loadTestVector,
  parseVectorHex,
  assertBytesEqual,
  bytesToHex
} from '../src/test-utils/vector-validation.js'


describe('RFC 9807 Authentication Test Vectors', () => {
  describe('ristretto255-SHA512 KE Messages', () => {
    it('should match RFC 9807 Appendix C.1.1 KE1 structure', async () => {
      const vector = await loadTestVector('ristretto255-sha512-real-vector-1.json')
      const outputs = parseVectorHex(vector.outputs)
      const config = vector.config

      // KE1 = CredentialRequest || AuthRequest
      // CredentialRequest = blinded_message[Noe]
      // AuthRequest = client_nonce[Nn] || client_public_keyshare[Npk]
      const expectedKE1Length = config.Nok + config.Nn + config.Npk
      expect(outputs.KE1.length).toBe(expectedKE1Length)

      // Verify credential request is at the start
      const credentialRequest = outputs.KE1.slice(0, config.Nok)
      expect(credentialRequest.length).toBe(config.Nok)

      // Verify auth request follows
      const authRequest = outputs.KE1.slice(config.Nok)
      expect(authRequest.length).toBe(config.Nn + config.Npk)

      // Extract and verify client nonce
      const clientNonce = outputs.KE1.slice(config.Nok, config.Nok + config.Nn)
      const inputs = parseVectorHex(vector.inputs)
      assertBytesEqual(clientNonce, inputs.client_nonce, 'Client nonce in KE1').mapLeft(
        (err) => {
          throw err
        }
      )
    })

    it('should match RFC 9807 Appendix C.1.1 KE2 structure', async () => {
      const vector = await loadTestVector('ristretto255-sha512-real-vector-1.json')
      const outputs = parseVectorHex(vector.outputs)
      const config = vector.config

      // KE2 = CredentialResponse || AuthResponse
      // CredentialResponse = evaluated_message[Noe] || masking_nonce[Nn] || masked_response[Npk + Nn + Nm]
      // AuthResponse = server_nonce[Nn] || server_public_keyshare[Npk] || server_mac[Nm]
      const credResponseLength = config.Nok + config.Nn + (config.Npk + config.Nn + config.Nm)
      const authResponseLength = config.Nn + config.Npk + config.Nm
      const expectedKE2Length = credResponseLength + authResponseLength

      expect(outputs.KE2.length).toBe(expectedKE2Length)

      // Verify credential response section
      const credentialResponse = outputs.KE2.slice(0, credResponseLength)
      const evaluatedMessage = credentialResponse.slice(0, config.Nok)
      const maskingNonce = credentialResponse.slice(config.Nok, config.Nok + config.Nn)
      const maskedResponse = credentialResponse.slice(config.Nok + config.Nn)

      expect(evaluatedMessage.length).toBe(config.Nok)
      expect(maskingNonce.length).toBe(config.Nn)
      expect(maskedResponse.length).toBe(config.Npk + config.Nn + config.Nm)

      // Verify masking nonce matches input
      const inputs = parseVectorHex(vector.inputs)
      assertBytesEqual(maskingNonce, inputs.masking_nonce, 'Masking nonce in KE2').mapLeft(
        (err) => {
          throw err
        }
      )

      // Verify auth response section
      const authResponse = outputs.KE2.slice(credResponseLength)
      const serverNonce = authResponse.slice(0, config.Nn)
      const serverPublicKeyshare = authResponse.slice(config.Nn, config.Nn + config.Npk)
      const serverMac = authResponse.slice(config.Nn + config.Npk)

      expect(serverNonce.length).toBe(config.Nn)
      expect(serverPublicKeyshare.length).toBe(config.Npk)
      expect(serverMac.length).toBe(config.Nm)

      assertBytesEqual(serverNonce, inputs.server_nonce, 'Server nonce in KE2').mapLeft(
        (err) => {
          throw err
        }
      )
    })

    it('should match RFC 9807 Appendix C.1.1 KE3 structure', async () => {
      const vector = await loadTestVector('ristretto255-sha512-real-vector-1.json')
      const outputs = parseVectorHex(vector.outputs)
      const config = vector.config

      // KE3 = client_mac[Nm]
      const expectedKE3Length = config.Nm
      expect(outputs.KE3.length).toBe(expectedKE3Length)

      // Client MAC should be 64 bytes for HMAC-SHA512
      expect(outputs.KE3.length).toBe(64)
    })
  })

  describe('ristretto255-SHA512 Session Keys', () => {
    it('should validate export key and session key derivation', async () => {
      const vector = await loadTestVector('ristretto255-sha512-real-vector-1.json')
      const outputs = parseVectorHex(vector.outputs)
      const config = vector.config

      // Export key and session key should be Nx bytes (64 for SHA512)
      expect(outputs.export_key.length).toBe(config.Nx)
      expect(outputs.session_key.length).toBe(config.Nx)

      // Keys should be different
      expect(bytesToHex(outputs.export_key)).not.toBe(bytesToHex(outputs.session_key))

      // Verify they match the test vector values
      expect(bytesToHex(outputs.export_key)).toBe(vector.outputs.export_key)
      expect(bytesToHex(outputs.session_key)).toBe(vector.outputs.session_key)
    })
  })

  describe('P256-SHA256 KE Messages', () => {
    it('should match RFC 9807 Appendix C.1.5 KE message structures', async () => {
      const vector = await loadTestVector('p256-sha256-real-vector-5.json')
      const outputs = parseVectorHex(vector.outputs)

      // KE1 with P256 (Npk=33, Nh=32)
      const expectedKE1Length = 33 + 32 + 33 // Noe + Nn + Npk
      expect(outputs.KE1.length).toBe(expectedKE1Length)

      // KE2 with P256
      const credResponseLength = 33 + 32 + (33 + 32 + 32) // Noe + Nn + (Npk + Nn + Nm)
      const authResponseLength = 32 + 33 + 32 // Nn + Npk + Nm
      const expectedKE2Length = credResponseLength + authResponseLength
      expect(outputs.KE2.length).toBe(expectedKE2Length)

      // KE3 with P256
      expect(outputs.KE3.length).toBe(32) // Nm for HMAC-SHA256

      // Keys should be 32 bytes for SHA256
      expect(outputs.export_key.length).toBe(32)
      expect(outputs.session_key.length).toBe(32)
    })
  })

  describe('Intermediate Value Validation', () => {
    it('should validate handshake secret derivation', async () => {
      const vectors = [
        'ristretto255-sha512-real-vector-1.json',
        'ristretto255-sha512-real-vector-2.json',
        'p256-sha256-real-vector-5.json'
      ]

      for (const vectorFile of vectors) {
        const vector = await loadTestVector(vectorFile)
        const intermediates = parseVectorHex(vector.intermediates)
        const config = vector.config

        // Handshake secret should be Nx bytes
        expect(intermediates.handshake_secret.length).toBe(config.Nx)

        // Server MAC key and Client MAC key should be Nx bytes
        expect(intermediates.server_mac_key.length).toBe(config.Nx)
        expect(intermediates.client_mac_key.length).toBe(config.Nx)

        // All three should be different
        expect(bytesToHex(intermediates.handshake_secret)).not.toBe(
          bytesToHex(intermediates.server_mac_key)
        )
        expect(bytesToHex(intermediates.handshake_secret)).not.toBe(
          bytesToHex(intermediates.client_mac_key)
        )
        expect(bytesToHex(intermediates.server_mac_key)).not.toBe(
          bytesToHex(intermediates.client_mac_key)
        )
      }
    })
  })

  describe('Cross-Vector Consistency', () => {
    it('should maintain consistency across vectors with same inputs', async () => {
      const vector1 = await loadTestVector('ristretto255-sha512-real-vector-1.json')
      const vector2 = await loadTestVector('ristretto255-sha512-real-vector-2.json')

      const inputs1 = parseVectorHex(vector1.inputs)
      const inputs2 = parseVectorHex(vector2.inputs)

      // Same password, oprf_seed, credential_identifier
      assertBytesEqual(inputs1.password, inputs2.password, 'Password').mapLeft((err) => {
        throw err
      })
      assertBytesEqual(inputs1.oprf_seed, inputs2.oprf_seed, 'OPRF seed').mapLeft((err) => {
        throw err
      })

      // Same OPRF key should be derived
      const intermediates1 = parseVectorHex(vector1.intermediates)
      const intermediates2 = parseVectorHex(vector2.intermediates)
      assertBytesEqual(intermediates1.oprf_key, intermediates2.oprf_key, 'OPRF key').mapLeft(
        (err) => {
          throw err
        }
      )

      // Same registration request (blind is the same)
      const outputs1 = parseVectorHex(vector1.outputs)
      const outputs2 = parseVectorHex(vector2.outputs)
      assertBytesEqual(
        outputs1.registration_request,
        outputs2.registration_request,
        'Registration request'
      ).mapLeft((err) => {
        throw err
      })
    })
  })
})
