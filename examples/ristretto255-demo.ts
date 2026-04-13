#!/usr/bin/env node
/**
 * Demonstration of ristretto255 cipher suite with Noble backend
 * 
 * This example shows how to enable and use ristretto255-SHA512
 * which requires the @noble/curves backend.
 */

import { configureNobleCrypto, getAvailableSuites, isRistretto255Available } from '../src/crypto-provider.js'
import { createOPRFConfig, createBoundOPRFOps } from '../src/oprf-functional.js'
import { Oprf } from '@cloudflare/voprf-ts'

async function main() {
    console.log('🚀 OPRF RFC 9497 - ristretto255 Demo\n')

    // Step 1: Configure noble crypto backend
    console.log('Step 1: Configuring Noble crypto backend...')
    await configureNobleCrypto()

    // Step 2: Check available suites
    console.log('\nStep 2: Checking available cipher suites...')
    const suites = getAvailableSuites()
    console.log('Available suites:', suites.join(', '))

    // Step 3: Verify ristretto255 is available
    console.log('\nStep 3: Checking ristretto255 availability...')
    if (!isRistretto255Available()) {
        console.error('❌ ristretto255 is not available!')
        console.log('Make sure @noble/curves is installed: pnpm add @noble/curves')
        process.exit(1)
    }
    console.log('✅ ristretto255-SHA512 is available!')

    // Step 4: Create OPRF configuration for ristretto255
    console.log('\nStep 4: Creating OPRF configuration for ristretto255...')
    const configResult = createOPRFConfig(Oprf.Suite.RISTRETTO255_SHA512)

    if (configResult.isLeft()) {
        console.error('❌ Failed to create config:', configResult.extract())
        process.exit(1)
    }

    const config = configResult.unsafeCoerce()
    console.log('✅ Config created:')
    console.log(`   Mode: ${config.mode} (modeOPRF)`)
    console.log(`   Hash: ${config.hash}`)
    console.log(`   Element size (Noe): ${config.Noe} bytes`)
    console.log(`   Group: ${config.groupName}`)

    // Step 5: Run a complete OPRF flow with ristretto255
    console.log('\nStep 5: Running complete OPRF flow...')

    const password = new TextEncoder().encode('correct-horse-battery-staple')
    const ops = createBoundOPRFOps(config)

    // Server: Generate key pair
    const keyPairResult = await ops.deriveKeyPair(new Uint8Array(32))
    if (keyPairResult.isLeft()) {
        console.error('❌ Failed to derive key:', keyPairResult.extract())
        process.exit(1)
    }
    const serverKey = keyPairResult.unsafeCoerce()
    console.log('✅ Server key generated')

    // Client: Blind password
    const blindResult = await ops.blind(password)
    if (blindResult.isLeft()) {
        console.error('❌ Failed to blind:', blindResult.extract())
        process.exit(1)
    }
    const { blindedElement, blind } = blindResult.unsafeCoerce()
    console.log('✅ Password blinded')
    console.log(`   Blinded element size: ${blindedElement.length} bytes`)

    // Server: Evaluate blinded element
    const evaluatedResult = await ops.evaluate(serverKey)(blindedElement)
    if (evaluatedResult.isLeft()) {
        console.error('❌ Failed to evaluate:', evaluatedResult.extract())
        process.exit(1)
    }
    const evaluated = evaluatedResult.unsafeCoerce()
    console.log('✅ Blinded element evaluated')
    console.log(`   Evaluated element size: ${evaluated.length} bytes`)

    // Client: Finalize to get OPRF output
    const finalizeResult = await ops.finalize({ input: password, blind, evaluation: evaluated })
    if (finalizeResult.isLeft()) {
        console.error('❌ Failed to finalize:', finalizeResult.extract())
        process.exit(1)
    }
    const output = finalizeResult.unsafeCoerce()
    console.log('✅ OPRF output computed')
    console.log(`   Output size: ${output.length} bytes`)
    console.log(`   Output (hex): ${Buffer.from(output).toString('hex').substring(0, 32)}...`)

    // Step 6: Verify determinism
    console.log('\nStep 6: Verifying deterministic behavior...')
    const output2Result = await ops.finalize({ input: password, blind, evaluation: evaluated })
    if (output2Result.isLeft()) {
        console.error('❌ Second finalize failed')
        process.exit(1)
    }
    const output2 = output2Result.unsafeCoerce()

    if (Buffer.from(output).equals(Buffer.from(output2))) {
        console.log('✅ Output is deterministic (same input → same output)')
    } else {
        console.error('❌ Output is not deterministic!')
        process.exit(1)
    }

    console.log('\n🎉 ristretto255 demo completed successfully!')
}

main().catch((err) => {
    console.error('Fatal error:', err)
    process.exit(1)
})
