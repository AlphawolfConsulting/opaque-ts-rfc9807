import { describe, it, expect } from '@jest/globals'
import {
  createHashOps,
  createHMAC,
  createKDFOps,
  generateRandomBytes
} from '../src/crypto/index.js'

describe('Functional Cryptographic Primitives', () => {
  describe('Hash Operations', () => {
    it('should hash with SHA-256', async () => {
      const opsResult = createHashOps('SHA-256')
      expect(opsResult.isRight()).toBe(true)
      const ops = opsResult.unsafeCoerce()
      const input = new TextEncoder().encode('test message')
      
      const result = await ops.hash(input)
      expect(result.isRight()).toBe(true)
      expect(result.unsafeCoerce().length).toBe(32)
    })
    
    it('should hash with SHA-512', async () => {
      const opsResult = createHashOps('SHA-512')
      expect(opsResult.isRight()).toBe(true)
      const ops = opsResult.unsafeCoerce()
      const input = new TextEncoder().encode('test message')
      
      const result = await ops.hash(input)
      expect(result.isRight()).toBe(true)
      expect(result.unsafeCoerce().length).toBe(64)
    })
    
    it('should produce same output for same input', async () => {
      const opsResult = createHashOps('SHA-256')
      expect(opsResult.isRight()).toBe(true)
      const ops = opsResult.unsafeCoerce()
      const input = new TextEncoder().encode('deterministic')
      
      const result1 = await ops.hash(input)
      const result2 = await ops.hash(input)
      
      expect(result1.unsafeCoerce()).toEqual(result2.unsafeCoerce())
    })
  })
  
  describe('HMAC Operations', () => {
    it('should sign and verify with HMAC-SHA256', async () => {
      const opsResult = createHMAC('SHA-256')
      expect(opsResult.isRight()).toBe(true)
      const ops = opsResult.unsafeCoerce()
      const key = new Uint8Array(32).fill(1)
      const message = new TextEncoder().encode('test message')
      
      const hmacOpsResult = await ops.withKey(key)
      expect(hmacOpsResult.isRight()).toBe(true)
      const hmacOps = hmacOpsResult.unsafeCoerce()
      
      const signature = await hmacOps.sign(message)
      expect(signature.isRight()).toBe(true)
      
      const tag = signature.unsafeCoerce()
      const valid = await hmacOps.verify(message)(tag)
      expect(valid.unsafeCoerce()).toBe(true)
    })
    
    it('should reject invalid tag', async () => {
      const opsResult = createHMAC('SHA-256')
      expect(opsResult.isRight()).toBe(true)
      const ops = opsResult.unsafeCoerce()
      const key = new Uint8Array(32).fill(1)
      const message = new TextEncoder().encode('test message')
      
      const hmacOpsResult = await ops.withKey(key)
      expect(hmacOpsResult.isRight()).toBe(true)
      const hmacOps = hmacOpsResult.unsafeCoerce()
      
      const invalidTag = new Uint8Array(32).fill(0)
      const valid = await hmacOps.verify(message)(invalidTag)
      expect(valid.unsafeCoerce()).toBe(false)
    })
  })
  
  describe('KDF Operations', () => {
    it('should extract and expand with HKDF', async () => {
      const opsResult = createKDFOps('SHA-256')
      expect(opsResult.isRight()).toBe(true)
      const ops = opsResult.unsafeCoerce()
      const salt = new Uint8Array(32).fill(0)
      const ikm = new TextEncoder().encode('input keying material')
      const info = new TextEncoder().encode('application info')
      
      const prk = await ops.extract(salt)(ikm)
      expect(prk.isRight()).toBe(true)
      
      const okm = await ops.expand(prk.unsafeCoerce())(info)(32)
      expect(okm.isRight()).toBe(true)
      expect(okm.unsafeCoerce().length).toBe(32)
    })
    
    it('should derive key in one step', async () => {
      const opsResult = createKDFOps('SHA-256')
      expect(opsResult.isRight()).toBe(true)
      const ops = opsResult.unsafeCoerce()
      const salt = new Uint8Array(32).fill(0)
      const ikm = new TextEncoder().encode('input keying material')
      const info = new TextEncoder().encode('application info')
      
      const okm = await ops.derive(salt, ikm, info, 32)
      expect(okm.isRight()).toBe(true)
      expect(okm.unsafeCoerce().length).toBe(32)
    })
  })
  
  describe('PRNG Operations', () => {
    it('should generate random bytes', () => {
      const result = generateRandomBytes(32)
      expect(result.isRight()).toBe(true)
      expect(result.unsafeCoerce().length).toBe(32)
    })
    
    it('should generate different random values', () => {
      const result1 = generateRandomBytes(32).unsafeCoerce()
      const result2 = generateRandomBytes(32).unsafeCoerce()
      expect(result1).not.toEqual(result2)
    })
    
    it('should fail for invalid length', () => {
      const result = generateRandomBytes(-1)
      expect(result.isLeft()).toBe(true)
    })
  })
  
  describe('Currying Behavior', () => {
    it('should allow partial application of hash', async () => {
      const opsResult = createHashOps('SHA-256')
      expect(opsResult.isRight()).toBe(true)
      const ops = opsResult.unsafeCoerce()
      const hash = ops.hash
      
      const msg1 = new TextEncoder().encode('message1')
      const msg2 = new TextEncoder().encode('message2')
      
      const result1 = await hash(msg1)
      const result2 = await hash(msg2)
      
      expect(result1.isRight()).toBe(true)
      expect(result2.isRight()).toBe(true)
      expect(result1.unsafeCoerce()).not.toEqual(result2.unsafeCoerce())
    })
  })
})
