// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// Tests for 3DH key schedule (RFC 9807 Section 6.2)

import { describe, it, expect } from '@jest/globals'
import {
    constructPreamble,
    computeTripleDHIKM,
    deriveKeys,
    create3DHOps
} from '../src/3dh-functional.js'
import { LABELS } from '../src/common.js'
import type { KE1, KE2 } from '../src/authentication-functional.js'
import { createId } from '@paralleldrive/cuid2'
import { OpaqueConfig, OpaqueID } from '../src/suites.js'

describe('3DH RFC 9807 Compliance', () => {
    // Helper to create test config
    const getConfig = (suite: 'P256' | 'P384' | 'P521' = 'P256') => {
        switch (suite) {
            case 'P256':
                return new OpaqueConfig(OpaqueID.OPAQUE_P256)
            case 'P384':
                return new OpaqueConfig(OpaqueID.OPAQUE_P384)
            case 'P521':
                return new OpaqueConfig(OpaqueID.OPAQUE_P521)
            default:
                return new OpaqueConfig(OpaqueID.OPAQUE_P256)
        }
    }

    describe('Preamble Construction (Section 6.2.2)', () => {
        it('should construct preamble with RFC9807 version', () => {
            const context = new Uint8Array([1, 2, 3])
            const client_identity = new Uint8Array([4, 5, 6])
            const server_identity = new Uint8Array([7, 8, 9])

            const ke1: KE1 = {
                credential_request: { data: new Uint8Array(32).fill(1) },
                auth_init: {
                    client_nonce: new Uint8Array(32).fill(2),
                    client_keyshare: new Uint8Array(32).fill(3)
                },
                sessionId: createId()
            }

            const ke2: KE2 = {
                credential_response: {
                    data: new Uint8Array(32).fill(4),
                    masking_nonce: new Uint8Array(32).fill(5),
                    masked_response: new Uint8Array(32).fill(6)
                },
                auth_response: {
                    server_nonce: new Uint8Array(32).fill(7),
                    server_keyshare: new Uint8Array(32).fill(8),
                    server_mac: new Uint8Array(32).fill(9)
                }
            }

            const preamble = constructPreamble(context, client_identity, ke1, server_identity, ke2)

            // Verify preamble starts with "RFC9807"
            const versionBytes = preamble.slice(0, LABELS.Version.length)
            expect(Array.from(versionBytes)).toEqual(Array.from(LABELS.Version))

            // Convert to string to verify
            const decoder = new TextDecoder()
            const versionString = decoder.decode(versionBytes)
            expect(versionString).toBe('RFC9807')

            // Verify preamble is not empty
            expect(preamble.length).toBeGreaterThan(LABELS.Version.length)
        })

        it('should include all components in correct order', () => {
            const context = new Uint8Array([0xaa])
            const client_identity = new Uint8Array([0xbb])
            const server_identity = new Uint8Array([0xcc])

            const ke1: KE1 = {
                credential_request: { data: new Uint8Array(10).fill(0x11) },
                auth_init: {
                    client_nonce: new Uint8Array(10).fill(0x22),
                    client_keyshare: new Uint8Array(10).fill(0x33)
                },
                sessionId: createId()
            }

            const ke2: KE2 = {
                credential_response: {
                    data: new Uint8Array(10).fill(0x44),
                    masking_nonce: new Uint8Array(10).fill(0x55),
                    masked_response: new Uint8Array(10).fill(0x66)
                },
                auth_response: {
                    server_nonce: new Uint8Array(10).fill(0x77),
                    server_keyshare: new Uint8Array(10).fill(0x88),
                    server_mac: new Uint8Array(10).fill(0x99)
                }
            }

            const preamble = constructPreamble(context, client_identity, ke1, server_identity, ke2)

            // Version should be at start
            expect(preamble[0]).toBe('R'.charCodeAt(0))

            // Verify structure has expected minimum length:
            // Version (7) + context_len (2) + context (1) + client_id_len (2) + client_id (1) +
            // ke1 (30) + server_id_len (2) + server_id (1) + credential_response (30) +
            // server_nonce (10) + server_keyshare (10) = at least 96 bytes
            expect(preamble.length).toBeGreaterThanOrEqual(96)
        })
    })

    describe('Triple-DH IKM (Section 6.2.1)', () => {
        it('should concatenate three DH shares', async () => {
            const dh1 = new Uint8Array(32).fill(1)
            const dh2 = new Uint8Array(32).fill(2)
            const dh3 = new Uint8Array(32).fill(3)

            const result = await computeTripleDHIKM(dh1)(dh2)(dh3)

            expect(result.isRight()).toBe(true)

            const ikm = result.unsafeCoerce()
            expect(ikm.length).toBe(96) // 3 * 32 bytes

            // Verify concatenation order
            expect(ikm.slice(0, 32)).toEqual(dh1)
            expect(ikm.slice(32, 64)).toEqual(dh2)
            expect(ikm.slice(64, 96)).toEqual(dh3)
        })

        it('should handle different sized DH shares', async () => {
            const dh1 = new Uint8Array(48).fill(0xaa)
            const dh2 = new Uint8Array(48).fill(0xbb)
            const dh3 = new Uint8Array(48).fill(0xcc)

            const result = await computeTripleDHIKM(dh1)(dh2)(dh3)

            expect(result.isRight()).toBe(true)
            const ikm = result.unsafeCoerce()
            expect(ikm.length).toBe(144) // 3 * 48 bytes
        })
    })

    describe('DeriveKeys (Section 6.2.3)', () => {
        it('should derive Km2, Km3, and session_key from IKM', async () => {
            const config = getConfig('P256')
            const ikm = new Uint8Array(96).fill(0x42)
            const preamble = new Uint8Array([...LABELS.Version, 0, 0]) // "RFC9807" + empty context

            const result = await deriveKeys(config)(ikm)(preamble)

            expect(result.isRight()).toBe(true)

            const keys = result.unsafeCoerce()
            expect(keys.Km2).toBeDefined()
            expect(keys.Km3).toBeDefined()
            expect(keys.session_key).toBeDefined()

            // All keys should have the hash output length
            expect(keys.Km2.length).toBe(config.hash.Nh)
            expect(keys.Km3.length).toBe(config.hash.Nh)
            expect(keys.session_key.length).toBe(config.hash.Nh)

            // Keys should be different
            expect(keys.Km2).not.toEqual(keys.Km3)
            expect(keys.Km2).not.toEqual(keys.session_key)
            expect(keys.Km3).not.toEqual(keys.session_key)
        })

        it('should produce deterministic keys for same inputs', async () => {
            const config = getConfig('P256')
            const ikm = new Uint8Array(96).fill(0x55)
            const preamble = new Uint8Array(100).fill(0x66)

            const result1 = await deriveKeys(config)(ikm)(preamble)
            const result2 = await deriveKeys(config)(ikm)(preamble)

            expect(result1.isRight()).toBe(true)
            expect(result2.isRight()).toBe(true)

            const keys1 = result1.unsafeCoerce()
            const keys2 = result2.unsafeCoerce()

            expect(keys1.Km2).toEqual(keys2.Km2)
            expect(keys1.Km3).toEqual(keys2.Km3)
            expect(keys1.session_key).toEqual(keys2.session_key)
        })

        it('should produce different keys for different IKM', async () => {
            const config = getConfig('P256')
            const ikm1 = new Uint8Array(96).fill(0x11)
            const ikm2 = new Uint8Array(96).fill(0x22)
            const preamble = new Uint8Array(100).fill(0x33)

            const result1 = await deriveKeys(config)(ikm1)(preamble)
            const result2 = await deriveKeys(config)(ikm2)(preamble)

            expect(result1.isRight()).toBe(true)
            expect(result2.isRight()).toBe(true)

            const keys1 = result1.unsafeCoerce()
            const keys2 = result2.unsafeCoerce()

            expect(keys1.Km2).not.toEqual(keys2.Km2)
            expect(keys1.Km3).not.toEqual(keys2.Km3)
            expect(keys1.session_key).not.toEqual(keys2.session_key)
        })

        it('should produce different keys for different preambles', async () => {
            const config = getConfig('P256')
            const ikm = new Uint8Array(96).fill(0x44)
            const preamble1 = new Uint8Array(100).fill(0x55)
            const preamble2 = new Uint8Array(100).fill(0x66)

            const result1 = await deriveKeys(config)(ikm)(preamble1)
            const result2 = await deriveKeys(config)(ikm)(preamble2)

            expect(result1.isRight()).toBe(true)
            expect(result2.isRight()).toBe(true)

            const keys1 = result1.unsafeCoerce()
            const keys2 = result2.unsafeCoerce()

            expect(keys1.Km2).not.toEqual(keys2.Km2)
            expect(keys1.Km3).not.toEqual(keys2.Km3)
            expect(keys1.session_key).not.toEqual(keys2.session_key)
        })
    })

    describe('Label Strings', () => {
        it('should have correct HandshakeSecret label', () => {
            const decoder = new TextDecoder()
            const label = decoder.decode(new Uint8Array(LABELS.HandshakeSecret))
            expect(label).toBe('HandshakeSecret')
        })

        it('should have correct SessionKey label', () => {
            const decoder = new TextDecoder()
            const label = decoder.decode(new Uint8Array(LABELS.SessionKey))
            expect(label).toBe('SessionKey')
        })

        it('should have correct ServerMAC label', () => {
            const decoder = new TextDecoder()
            const label = decoder.decode(new Uint8Array(LABELS.ServerMAC))
            expect(label).toBe('ServerMAC')
        })

        it('should have correct ClientMAC label', () => {
            const decoder = new TextDecoder()
            const label = decoder.decode(new Uint8Array(LABELS.ClientMAC))
            expect(label).toBe('ClientMAC')
        })

        it('should have correct Version label (RFC9807)', () => {
            const decoder = new TextDecoder()
            const version = decoder.decode(new Uint8Array(LABELS.Version))
            expect(version).toBe('RFC9807')
        })
    })

    describe('Bound 3DH Operations', () => {
        it('should create bound operations with config', () => {
            const config = getConfig('P256')
            const ops = create3DHOps(config)

            expect(ops.constructPreamble).toBeDefined()
            expect(ops.computeTripleDHIKM).toBeDefined()
            expect(ops.deriveKeys).toBeDefined()

            expect(typeof ops.constructPreamble).toBe('function')
            expect(typeof ops.computeTripleDHIKM).toBe('function')
            expect(typeof ops.deriveKeys).toBe('function')
        })

        it('should work through bound operations interface', async () => {
            const config = getConfig('P256')
            const ops = create3DHOps(config)

            // Test computeTripleDHIKM
            const dh1 = new Uint8Array(32).fill(1)
            const dh2 = new Uint8Array(32).fill(2)
            const dh3 = new Uint8Array(32).fill(3)

            const ikmResult = await ops.computeTripleDHIKM(dh1, dh2, dh3)
            expect(ikmResult.isRight()).toBe(true)

            const ikm = ikmResult.unsafeCoerce()

            // Test constructPreamble
            const context = new Uint8Array([1, 2, 3])
            const client_identity = new Uint8Array([4, 5, 6])
            const server_identity = new Uint8Array([7, 8, 9])

            const ke1: KE1 = {
                credential_request: { data: new Uint8Array(32).fill(1) },
                auth_init: {
                    client_nonce: new Uint8Array(32).fill(2),
                    client_keyshare: new Uint8Array(32).fill(3)
                },
                sessionId: createId()
            }

            const ke2: KE2 = {
                credential_response: {
                    data: new Uint8Array(32).fill(4),
                    masking_nonce: new Uint8Array(32).fill(5),
                    masked_response: new Uint8Array(32).fill(6)
                },
                auth_response: {
                    server_nonce: new Uint8Array(32).fill(7),
                    server_keyshare: new Uint8Array(32).fill(8),
                    server_mac: new Uint8Array(32).fill(9)
                }
            }

            const preamble = ops.constructPreamble(
                context,
                client_identity,
                ke1,
                server_identity,
                ke2
            )

            // Test deriveKeys
            const keysResult = await ops.deriveKeys(ikm, preamble)
            expect(keysResult.isRight()).toBe(true)

            const keys = keysResult.unsafeCoerce()
            expect(keys.Km2).toBeDefined()
            expect(keys.Km3).toBeDefined()
            expect(keys.session_key).toBeDefined()
        })
    })

    describe('RFC 9807 Compliance', () => {
        it('should use RFC9807 version in preamble (not OPAQUEv1-)', () => {
            const decoder = new TextDecoder()
            const version = decoder.decode(new Uint8Array(LABELS.Version))

            // Verify it's RFC9807, not OPAQUEv1-
            expect(version).toBe('RFC9807')
            expect(version).not.toBe('OPAQUEv1-')
            expect(version).not.toContain('OPAQUE')
        })

        it('should follow RFC 9807 Section 6.2.2 preamble structure', () => {
            // Preamble format from RFC 9807:
            // "RFC9807" || I2OSP(len(context), 2) || context ||
            // I2OSP(len(client_identity), 2) || client_identity ||
            // ke1 || I2OSP(len(server_identity), 2) || server_identity ||
            // ke2.credential_response || ke2.auth_response.server_nonce ||
            // ke2.auth_response.server_keyshare

            const context = new Uint8Array([0xaa, 0xbb])
            const client_identity = new Uint8Array([0xcc])
            const server_identity = new Uint8Array([0xdd, 0xee])

            const ke1: KE1 = {
                credential_request: { data: new Uint8Array(5).fill(0x11) },
                auth_init: {
                    client_nonce: new Uint8Array(5).fill(0x22),
                    client_keyshare: new Uint8Array(5).fill(0x33)
                },
                sessionId: createId()
            }

            const ke2: KE2 = {
                credential_response: {
                    data: new Uint8Array(5).fill(0x44),
                    masking_nonce: new Uint8Array(5).fill(0x55),
                    masked_response: new Uint8Array(5).fill(0x66)
                },
                auth_response: {
                    server_nonce: new Uint8Array(5).fill(0x77),
                    server_keyshare: new Uint8Array(5).fill(0x88),
                    server_mac: new Uint8Array(5).fill(0x99)
                }
            }

            const preamble = constructPreamble(context, client_identity, ke1, server_identity, ke2)

            let offset = 0

            // Check "RFC9807"
            const versionBytes = preamble.slice(offset, offset + LABELS.Version.length)
            expect(Array.from(versionBytes)).toEqual(Array.from(LABELS.Version))
            offset += LABELS.Version.length

            // Check context length (I2OSP 2 bytes)
            expect(preamble[offset]).toBe(0) // high byte
            expect(preamble[offset + 1]).toBe(2) // low byte = 2
            offset += 2

            // Check context
            expect(preamble.slice(offset, offset + 2)).toEqual(context)
            offset += 2

            // Check client_identity length
            expect(preamble[offset]).toBe(0) // high byte
            expect(preamble[offset + 1]).toBe(1) // low byte = 1
            offset += 2

            // Check client_identity
            expect(preamble[offset]).toBe(0xcc)
        })
    })
})
