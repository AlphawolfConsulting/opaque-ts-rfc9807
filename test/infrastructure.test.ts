import { Right } from 'purify-ts'
import { opaqueLogger, opaqueLoader } from '../src/opaque-config.js'
import { curry2, tryCatch, eitherToResult } from '../src/functional-utils.js'

describe('Infrastructure', () => {
    it('should import purify-ts', () => {
        const result = Right(42)
        expect(result.isRight()).toBe(true)
    })

    it('should generate cryptographically secure random bytes', () => {
        const bytes = crypto.getRandomValues(new Uint8Array(32))
        expect(bytes.length).toBe(32)
        // Verify it's not all zeros
        const sum = Array.from(bytes).reduce((a, b) => a + b, 0)
        expect(sum).toBeGreaterThan(0)
    })

    it('should have logger', () => {
        expect(opaqueLogger).toBeDefined()
    })

    it('should have loader', () => {
        expect(opaqueLoader).toBeDefined()
    })

    it('should curry functions', () => {
        const add = (a: number, b: number) => a + b
        const curriedAdd = curry2(add)
        expect(curriedAdd(2)(3)).toBe(5)
    })

    it('should use tryCatch for error handling', () => {
        const safe = tryCatch(() => {
            throw new Error('test error')
        })
        expect(safe.isLeft()).toBe(true)

        const success = tryCatch(() => 42)
        expect(success.isRight()).toBe(true)
        expect(success.extract()).toBe(42)
    })

    it('should convert Either to Result', () => {
        const right = Right(10)
        const result = eitherToResult(right)
        expect(result.ok).toBe(true)
        if (result.ok) {
            expect(result.value).toBe(10)
        }
    })

    it('should use Maybe for optional values', async () => {
        const { safeArrayGet } = await import('../src/functional-utils.js')
        const arr = [1, 2, 3]
        const found = safeArrayGet(arr, 1)
        expect(found.isJust()).toBe(true)

        const notFound = safeArrayGet(arr, 10)
        expect(notFound.isNothing()).toBe(true)
    })
})
