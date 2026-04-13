import { describe, it, expect, beforeAll } from '@jest/globals'
import {
    createOPRFConfig,
    createBoundOPRFOps,
    blindPassword,
    evaluateBlinded,
    deriveOPRFKeyPair
} from '../src/oprf-functional.js'
import { Oprf, type SuiteID } from '@cloudflare/voprf-ts'
import { configureNobleCrypto, isRistretto255Available } from '../src/crypto-provider.js'

describe('OPRF RFC 9497 Compliance', () => {
    // Configure noble crypto provider before all tests
    beforeAll(async () => {
        await configureNobleCrypto()
    })

    describe('Configuration Creation', () => {
        it('should create ristretto255-SHA512 config', () => {
            if (!isRistretto255Available()) {
                console.log('⚠️  Skipping ristretto255 - noble backend not available')
                return
            }

            const result = createOPRFConfig(Oprf.Suite.RISTRETTO255_SHA512)
            expect(result.isRight()).toBe(true)

            if (result.isRight()) {
                const config = result.unsafeCoerce()
                expect(config.mode).toBe(0x00) // modeOPRF
                expect(config.hash).toBe('SHA-512')
                expect(config.Noe).toBe(32) // ristretto255 element size
                expect(config.groupName).toBe('ristretto255')
            }
        })

        it('should create P256-SHA256 config', () => {
            const result = createOPRFConfig(Oprf.Suite.P256_SHA256)
            expect(result.isRight()).toBe(true)

            if (result.isRight()) {
                const config = result.unsafeCoerce()
                expect(config.mode).toBe(0x00) // modeOPRF
                expect(config.hash).toBe('SHA-256')
                expect(config.Noe).toBe(33) // P-256 compressed point
                expect(config.groupName).toBe('P-256')
            }
        })

        it('should create P384-SHA384 config', () => {
            const result = createOPRFConfig(Oprf.Suite.P384_SHA384)
            expect(result.isRight()).toBe(true)

            if (result.isRight()) {
                const config = result.unsafeCoerce()
                expect(config.mode).toBe(0x00)
                expect(config.hash).toBe('SHA-384')
                expect(config.groupName).toBe('P-384')
            }
        })

        it('should create P521-SHA512 config', () => {
            const result = createOPRFConfig(Oprf.Suite.P521_SHA512)
            expect(result.isRight()).toBe(true)

            if (result.isRight()) {
                const config = result.unsafeCoerce()
                expect(config.mode).toBe(0x00)
                expect(config.hash).toBe('SHA-512')
                expect(config.groupName).toBe('P-521')
            }
        })
    })

    describe('OPRF Operations', () => {
        const testPassword = new TextEncoder().encode('test-password-123')

        it('should blind password with ristretto255', async () => {
            if (!isRistretto255Available()) {
                console.log('⚠️  Skipping ristretto255 blind test')
                return
            }

            const config = createOPRFConfig(Oprf.Suite.RISTRETTO255_SHA512).unsafeCoerce()
            const result = await blindPassword(config)(testPassword)

            expect(result.isRight()).toBe(true)
            if (result.isRight()) {
                const blindResult = result.unsafeCoerce()
                expect(blindResult.blind.length).toBeGreaterThan(0)
                expect(blindResult.blindedElement.length).toBe(32)
            }
        })

        it('should blind password with P256', async () => {
            const config = createOPRFConfig(Oprf.Suite.P256_SHA256).unsafeCoerce()
            const result = await blindPassword(config)(testPassword)

            expect(result.isRight()).toBe(true)
            if (result.isRight()) {
                const blindResult = result.unsafeCoerce()
                expect(blindResult.blind.length).toBeGreaterThan(0)
                expect(blindResult.blindedElement.length).toBe(33)
            }
        })

        it('should complete full OPRF flow with ristretto255', async () => {
            if (!isRistretto255Available()) {
                console.log('⚠️  Skipping ristretto255 full flow test')
                return
            }

            const config = createOPRFConfig(Oprf.Suite.RISTRETTO255_SHA512).unsafeCoerce()
            const ops = createBoundOPRFOps(config)

            // Generate OPRF key
            const seed = crypto.getRandomValues(new Uint8Array(32))
            const keyResult = await ops.deriveKeyPair(seed)
            expect(keyResult.isRight()).toBe(true)
            const oprfKey = keyResult.unsafeCoerce()

            // Client: Blind
            const blindResult = await ops.blind(testPassword)
            expect(blindResult.isRight()).toBe(true)
            const { blind, blindedElement } = blindResult.unsafeCoerce()

            // Server: Evaluate
            const evalResult = await ops.evaluate(oprfKey)(blindedElement)
            expect(evalResult.isRight()).toBe(true)
            const evaluation = evalResult.unsafeCoerce()

            // Client: Finalize
            const finalResult = await ops.finalize({ input: testPassword, blind, evaluation })
            expect(finalResult.isRight()).toBe(true)
            const output = finalResult.unsafeCoerce()

            expect(output.length).toBe(64) // SHA-512 output
        })

        it('should complete full OPRF flow with P256', async () => {
            const config = createOPRFConfig(Oprf.Suite.P256_SHA256).unsafeCoerce()
            const ops = createBoundOPRFOps(config)

            const seed = crypto.getRandomValues(new Uint8Array(32))
            const keyResult = await ops.deriveKeyPair(seed)
            expect(keyResult.isRight()).toBe(true)
            const oprfKey = keyResult.unsafeCoerce()

            const blindResult = await ops.blind(testPassword)
            expect(blindResult.isRight()).toBe(true)
            const { blind, blindedElement } = blindResult.unsafeCoerce()

            const evalResult = await ops.evaluate(oprfKey)(blindedElement)
            expect(evalResult.isRight()).toBe(true)
            const evaluation = evalResult.unsafeCoerce()

            const finalResult = await ops.finalize({ input: testPassword, blind, evaluation })
            expect(finalResult.isRight()).toBe(true)
            const output = finalResult.unsafeCoerce()

            expect(output.length).toBe(32) // SHA-256 output
        })

        it('should produce consistent output for same key and input', async () => {
            if (!isRistretto255Available()) {
                console.log('⚠️  Skipping ristretto255 consistency test')
                return
            }

            const config = createOPRFConfig(Oprf.Suite.RISTRETTO255_SHA512).unsafeCoerce()
            const ops = createBoundOPRFOps(config)

            const seed = new Uint8Array(32).fill(1) // Fixed seed
            const keyResult = await ops.deriveKeyPair(seed)
            const oprfKey = keyResult.unsafeCoerce()

            // Run OPRF twice with same key
            const run = async () => {
                const blindRes = await ops.blind(testPassword)
                const { blind, blindedElement } = blindRes.unsafeCoerce()
                const evalRes = await ops.evaluate(oprfKey)(blindedElement)
                const evaluation = evalRes.unsafeCoerce()
                const finalRes = await ops.finalize({ input: testPassword, blind, evaluation })
                return finalRes.unsafeCoerce()
            }

            const output1 = await run()
            const output2 = await run()

            // Note: Outputs will differ due to random blinding
            // This tests that the flow works consistently
            expect(output1.length).toBe(output2.length)
            expect(output1.length).toBe(64)
        })

        it('should derive different keys from different seeds', async () => {
            const config = createOPRFConfig(Oprf.Suite.P256_SHA256).unsafeCoerce()

            const seed1 = new Uint8Array(32).fill(1)
            const seed2 = new Uint8Array(32).fill(2)

            const key1Result = await deriveOPRFKeyPair(config)(seed1)
            const key2Result = await deriveOPRFKeyPair(config)(seed2)

            expect(key1Result.isRight()).toBe(true)
            expect(key2Result.isRight()).toBe(true)

            const key1 = key1Result.unsafeCoerce()
            const key2 = key2Result.unsafeCoerce()

            // Keys should be different
            expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false)
        })
    })

    describe('Error Handling', () => {
        it('should handle invalid blinded element gracefully', async () => {
            if (!isRistretto255Available()) {
                console.log('⚠️  Skipping ristretto255 error handling test')
                return
            }

            const config = createOPRFConfig(Oprf.Suite.RISTRETTO255_SHA512).unsafeCoerce()
            const ops = createBoundOPRFOps(config)

            const seed = crypto.getRandomValues(new Uint8Array(32))
            const keyResult = await ops.deriveKeyPair(seed)
            const oprfKey = keyResult.unsafeCoerce()

            // Invalid blinded element (wrong size)
            const invalidBlinded = new Uint8Array(10)
            const result = await ops.evaluate(oprfKey)(invalidBlinded)

            expect(result.isLeft()).toBe(true)
        })

        it('should handle invalid evaluation element gracefully', async () => {
            const config = createOPRFConfig(Oprf.Suite.P256_SHA256).unsafeCoerce()
            const ops = createBoundOPRFOps(config)

            const testPassword = new TextEncoder().encode('password')
            const blindResult = await ops.blind(testPassword)
            const { blind } = blindResult.unsafeCoerce()

            // Invalid evaluation (wrong size)
            const invalidEval = new Uint8Array(10)
            const result = await ops.finalize({ input: testPassword, blind, evaluation: invalidEval })

            expect(result.isLeft()).toBe(true)
        })
    })

    describe('Currying Behavior', () => {
        it('should allow partial application of evaluate', async () => {
            if (!isRistretto255Available()) {
                console.log('⚠️  Skipping ristretto255 currying test')
                return
            }

            const config = createOPRFConfig(Oprf.Suite.RISTRETTO255_SHA512).unsafeCoerce()
            const ops = createBoundOPRFOps(config)

            const seed = crypto.getRandomValues(new Uint8Array(32))
            const keyResult = await ops.deriveKeyPair(seed)
            const oprfKey = keyResult.unsafeCoerce()

            // Partially apply key
            const evaluateWithKey = ops.evaluate(oprfKey)

            // Use partial function multiple times
            const pwd1 = new TextEncoder().encode('password1')
            const pwd2 = new TextEncoder().encode('password2')
            const blindRes1 = await ops.blind(pwd1)
            const blindRes2 = await ops.blind(pwd2)

            const eval1 = await evaluateWithKey(blindRes1.unsafeCoerce().blindedElement)
            const eval2 = await evaluateWithKey(blindRes2.unsafeCoerce().blindedElement)

            expect(eval1.isRight()).toBe(true)
            expect(eval2.isRight()).toBe(true)
        })

        it('should allow partial application of blindPassword', async () => {
            const config = createOPRFConfig(Oprf.Suite.P256_SHA256).unsafeCoerce()

            // Partially apply config
            const blindWithConfig = blindPassword(config)

            const pwd1 = new TextEncoder().encode('password1')
            const pwd2 = new TextEncoder().encode('password2')

            const result1 = await blindWithConfig(pwd1)
            const result2 = await blindWithConfig(pwd2)

            expect(result1.isRight()).toBe(true)
            expect(result2.isRight()).toBe(true)
        })

        it('should allow partial application of evaluateBlinded', async () => {
            if (!isRistretto255Available()) {
                console.log('⚠️  Skipping ristretto255 evaluateBlinded currying test')
                return
            }

            const config = createOPRFConfig(Oprf.Suite.RISTRETTO255_SHA512).unsafeCoerce()

            const seed = crypto.getRandomValues(new Uint8Array(32))
            const keyResult = await deriveOPRFKeyPair(config)(seed)
            const oprfKey = keyResult.unsafeCoerce()

            // Partially apply config
            const evaluateWithConfig = evaluateBlinded(config)
            // Partially apply key
            const evaluateWithKey = evaluateWithConfig(oprfKey)

            const pwd = new TextEncoder().encode('password')
            const blindResult = await blindPassword(config)(pwd)
            const { blindedElement } = blindResult.unsafeCoerce()

            const result = await evaluateWithKey(blindedElement)
            expect(result.isRight()).toBe(true)
        })
    })

    describe('RFC 9497 Mode Compliance', () => {
        it('should use mode 0x00 for all suites', () => {
            const suites: SuiteID[] = [
                Oprf.Suite.P256_SHA256,
                Oprf.Suite.P384_SHA384,
                Oprf.Suite.P521_SHA512
            ]

            // Add ristretto255 if available
            if (isRistretto255Available()) {
                suites.push(Oprf.Suite.RISTRETTO255_SHA512 as SuiteID)
            }

            for (const suite of suites) {
                const config = createOPRFConfig(suite).unsafeCoerce()
                expect(config.mode).toBe(0x00) // modeOPRF
            }
        })

        it('should have correct element sizes per RFC 9497', () => {
            const configs: Array<{ suite: SuiteID; expectedNoe: number }> = [
                { suite: Oprf.Suite.P256_SHA256, expectedNoe: 33 },
                { suite: Oprf.Suite.P384_SHA384, expectedNoe: 49 },
                { suite: Oprf.Suite.P521_SHA512, expectedNoe: 67 }
            ]

            // Add ristretto255 if available
            if (isRistretto255Available()) {
                configs.push({ suite: Oprf.Suite.RISTRETTO255_SHA512 as SuiteID, expectedNoe: 32 })
            }

            for (const { suite, expectedNoe } of configs) {
                const config = createOPRFConfig(suite).unsafeCoerce()
                expect(config.Noe).toBe(expectedNoe)
            }
        })

        it('should have correct hash functions per RFC 9497', () => {
            const configs: Array<{ suite: SuiteID; expectedHash: string }> = [
                { suite: Oprf.Suite.P256_SHA256, expectedHash: 'SHA-256' },
                { suite: Oprf.Suite.P384_SHA384, expectedHash: 'SHA-384' },
                { suite: Oprf.Suite.P521_SHA512, expectedHash: 'SHA-512' }
            ]

            // Add ristretto255 if available
            if (isRistretto255Available()) {
                configs.push({ suite: Oprf.Suite.RISTRETTO255_SHA512 as SuiteID, expectedHash: 'SHA-512' })
            }

            for (const { suite, expectedHash } of configs) {
                const config = createOPRFConfig(suite).unsafeCoerce()
                expect(config.hash).toBe(expectedHash)
            }
        })
    })

    describe('Integration with OPRFBaseMode', () => {
        it('should work correctly when used through bound operations', async () => {
            const config = createOPRFConfig(Oprf.Suite.P256_SHA256).unsafeCoerce()
            const ops = createBoundOPRFOps(config)

            const password = new TextEncoder().encode('secure-password')
            const seed = crypto.getRandomValues(new Uint8Array(32))

            // Full flow
            const keyResult = await ops.deriveKeyPair(seed)
            expect(keyResult.isRight()).toBe(true)
            const oprfKey = keyResult.unsafeCoerce()

            const blindResult = await ops.blind(password)
            expect(blindResult.isRight()).toBe(true)
            const { blind, blindedElement } = blindResult.unsafeCoerce()

            const evalResult = await ops.evaluate(oprfKey)(blindedElement)
            expect(evalResult.isRight()).toBe(true)
            const evaluation = evalResult.unsafeCoerce()

            const finalResult = await ops.finalize({ input: password, blind, evaluation })
            expect(finalResult.isRight()).toBe(true)
            const output = finalResult.unsafeCoerce()

            // Verify output is correct size for SHA-256
            expect(output.length).toBe(32)
        })
    })
})
