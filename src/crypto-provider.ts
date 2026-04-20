// Copyright (c) 2026 - OPAQUE RFC 9807 Implementation
// Crypto provider configuration for voprf-ts with @noble/curves support

import { Oprf } from '@cloudflare/voprf-ts'

/**
 * Configure the Noble crypto provider for ristretto255 and decaf448 support
 *
 * This enables the full suite of RFC 9497 cipher suites including:
 * - P-256-SHA256 (default sjcl backend)
 * - P-384-SHA384 (default sjcl backend)
 * - P-521-SHA512 (default sjcl backend)
 * - ristretto255-SHA512 (requires noble backend) ✅
 * - decaf448-SHAKE256 (requires noble backend) ✅
 *
 * @see https://github.com/cloudflare/voprf-ts#readme
 */
export async function configureNobleCrypto(): Promise<void> {
    try {
        // Import the pre-configured noble crypto provider from voprf-ts
        // Package exports it as '@cloudflare/voprf-ts/crypto-noble'
        // TypeScript's "node" moduleResolution doesn't understand package.json exports,
        // but the import works at runtime (and with "node16"/"nodenext" moduleResolution)
        const cryptoNobleModule = (await import(
            // @ts-expect-error - TypeScript "node" moduleResolution doesn't support package.json exports
            '@cloudflare/voprf-ts/crypto-noble'
        )) as { CryptoNoble: typeof Oprf.Crypto }
        const CryptoNoble = cryptoNobleModule.CryptoNoble

        // Set as the global crypto provider for voprf-ts
        Oprf.Crypto = CryptoNoble

        console.log('✅ Noble crypto provider configured - ristretto255 and decaf448 enabled')
    } catch (error) {
        console.warn(
            '⚠️  Failed to configure Noble crypto provider:',
            error instanceof Error ? error.message : error
        )
        console.warn(
            '   ristretto255 and decaf448 will not be available. P-256/P-384/P-521 still work.'
        )
    }
}

/**
 * Check if ristretto255 is available
 */
export function isRistretto255Available(): boolean {
    try {
        // Try to get the ristretto255 group
        Oprf.getGroup(Oprf.Suite.RISTRETTO255_SHA512)
        return true
    } catch {
        return false
    }
}

/**
 * Check if decaf448 is available
 */
export function isDecaf448Available(): boolean {
    try {
        // Try to get the decaf448 group
        Oprf.getGroup(Oprf.Suite.DECAF448_SHAKE256)
        return true
    } catch {
        return false
    }
}

/**
 * Get list of available cipher suites
 */
export function getAvailableSuites(): readonly string[] {
    const suites: string[] = []

    // NIST curves always available with default backend
    suites.push(Oprf.Suite.P256_SHA256)
    suites.push(Oprf.Suite.P384_SHA384)
    suites.push(Oprf.Suite.P521_SHA512)

    // Check for noble backend suites
    if (isRistretto255Available()) {
        suites.push(Oprf.Suite.RISTRETTO255_SHA512)
    }

    if (isDecaf448Available()) {
        suites.push(Oprf.Suite.DECAF448_SHAKE256)
    }

    return suites
}
