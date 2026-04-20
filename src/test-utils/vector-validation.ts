// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// Test vector validation utilities for RFC 9807 compliance

import type { Either } from 'purify-ts'
import { Right, Left } from 'purify-ts'
import { readFile } from 'fs/promises'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

// ES Module __dirname equivalent
const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

/**
 * Convert hex string to Uint8Array
 * @pure
 */
export const hexToBytes = (hex: string): Uint8Array => {
    const cleaned = hex.replace(/\s/g, '')
    if (cleaned.length % 2 !== 0) {
        throw new Error(`Invalid hex string length: ${cleaned.length}`)
    }
    const bytes = new Uint8Array(cleaned.length / 2)
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(cleaned.substr(i * 2, 2), 16)
    }
    return bytes
}

/**
 * Convert Uint8Array to hex string
 * @pure
 */
export const bytesToHex = (bytes: Uint8Array): string => {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
}

/**
 * Compare two byte arrays for equality
 * @pure
 */
export const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false
    }
    return true
}

/**
 * Assert bytes match expected value
 */
export const assertBytesEqual = (
    actual: Uint8Array,
    expected: Uint8Array,
    label: string
): Either<Error, void> => {
    if (bytesEqual(actual, expected)) {
        return Right(undefined)
    }

    const errorMsg =
        `${label} mismatch:\n` +
        `  Expected: ${bytesToHex(expected)}\n` +
        `  Actual:   ${bytesToHex(actual)}`

    return Left(new Error(errorMsg))
}

/**
 * Load test vector from JSON file
 */
export const loadTestVector = async (filename: string): Promise<any> => {
    // When compiled, this file is in lib/src/test-utils/, need to go up to project root
    const vectorPath = join(__dirname, '../../../test/vectors-rfc9807', filename)
    const content = await readFile(vectorPath, 'utf-8')
    return JSON.parse(content)
}

/**
 * Parse test vector hex values to Uint8Arrays
 */
export const parseVectorHex = <T extends Record<string, any>>(
    obj: T
): { readonly [K in keyof T]: Uint8Array } => {
    const parsed: any = {}
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
            parsed[key] = hexToBytes(value)
        }
    }
    return parsed
}

/**
 * Parse optional test vector hex values (handles nil/undefined)
 */
export const parseOptionalVectorHex = <T extends Record<string, any>>(
    obj: T
): { readonly [K in keyof T]: Uint8Array | undefined } => {
    const parsed: any = {}
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string' && value.length > 0) {
            parsed[key] = hexToBytes(value)
        } else {
            parsed[key] = undefined
        }
    }
    return parsed
}

/**
 * Validate configuration parameters match expected values
 */
export const validateConfig = (
    actualConfig: Record<string, any>,
    expectedConfig: Record<string, any>,
    label: string
): Either<Error, void> => {
    const errors: string[] = []

    for (const [key, expectedValue] of Object.entries(expectedConfig)) {
        const actualValue = actualConfig[key]
        if (actualValue !== expectedValue) {
            errors.push(`  ${key}: expected ${expectedValue}, got ${actualValue}`)
        }
    }

    if (errors.length > 0) {
        return Left(new Error(`${label} configuration mismatch:\n${errors.join('\n')}`))
    }

    return Right(undefined)
}

/**
 * Format test vector for display
 */
export const formatTestVector = (vector: any): string => {
    return JSON.stringify(vector, null, 2)
}
