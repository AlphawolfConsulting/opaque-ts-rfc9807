// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { scrypt } from '@noble/hashes/scrypt'

import {
    createHashOps,
    createHMAC,
    createKDFOps,
    generateRandomBytes,
    type HashAlgorithm,
    type BoundHashOps,
    type BoundHMACOps,
    type BoundKDFOps
} from './crypto/index.js'

export interface PrngFn {
    random(numBytes: number): number[]
}

export class Prng implements PrngFn {
    /* eslint-disable-next-line class-methods-use-this */
    random(numBytes: number): number[] {
        // Use functional wrapper internally
        const result = generateRandomBytes(numBytes)
        if (result.isLeft()) {
            throw result.unsafeCoerce()
        }
        return Array.from(result.unsafeCoerce())
    }
}

export interface HashFn {
    name: string
    Nh: number //  Nh: The output size of the Hash function in bytes.
    sum(msg: Uint8Array): Promise<Uint8Array>
}

export class Hash implements HashFn {
    readonly Nh: number
    private readonly ops: BoundHashOps

    constructor(public readonly name: string) {
        // Use functional wrapper internally
        const opsResult = createHashOps(name as HashAlgorithm)
        if (opsResult.isLeft()) {
            throw opsResult.unsafeCoerce()
        }
        this.ops = opsResult.unsafeCoerce()
        this.Nh = this.ops.config.Nh
    }

    async sum(msg: Uint8Array): Promise<Uint8Array> {
        const result = await this.ops.hash(msg)
        if (result.isLeft()) {
            throw result.unsafeCoerce()
        }
        return result.unsafeCoerce()
    }
}

/* eslint-disable-next-line @typescript-eslint/no-namespace */
export namespace Hash {
    export const ID = {
        SHA1: 'SHA-1',
        SHA256: 'SHA-256',
        SHA384: 'SHA-384',
        SHA512: 'SHA-512'
    } as const
    export type ID = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
}

export interface MACOps {
    sign(msg: Uint8Array): Promise<Uint8Array>
    verify(msg: Uint8Array, output: Uint8Array): Promise<boolean>
}

export interface MACFn {
    Nm: number // The output size of the MAC() function in bytes.
    with_key(key: Uint8Array): Promise<MACOps>
}

export class Hmac implements MACFn {
    readonly Nm: number
    private readonly ops: BoundHMACOps

    constructor(readonly hash: string) {
        // Use functional wrapper internally
        const opsResult = createHMAC(hash as HashAlgorithm)
        if (opsResult.isLeft()) {
            throw opsResult.unsafeCoerce()
        }
        this.ops = opsResult.unsafeCoerce()
        this.Nm = this.ops.config.Nm
    }

    async with_key(key: Uint8Array): Promise<MACOps> {
        const opsResult = await this.ops.withKey(key)
        if (opsResult.isLeft()) {
            throw opsResult.unsafeCoerce()
        }
        const hmacOps = opsResult.unsafeCoerce()
        
        return {
            sign: async (msg: Uint8Array) => {
                const result = await hmacOps.sign(msg)
                if (result.isLeft()) throw result.unsafeCoerce()
                return result.unsafeCoerce()
            },
            verify: async (msg: Uint8Array, output: Uint8Array) => {
                const result = await hmacOps.verify(msg)(output)
                if (result.isLeft()) throw result.unsafeCoerce()
                return result.unsafeCoerce()
            }
        }
    }
}

export interface KDFFn {
    Nx: number // The output size of the Extract() function in bytes.
    extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>
    expand(prk: Uint8Array, info: Uint8Array, lenBytes: number): Promise<Uint8Array>
}

export class Hkdf implements KDFFn {
    readonly Nx: number
    private readonly ops: BoundKDFOps

    constructor(public hash: string) {
        // Use functional wrapper internally
        const opsResult = createKDFOps(hash as HashAlgorithm)
        if (opsResult.isLeft()) {
            throw opsResult.unsafeCoerce()
        }
        this.ops = opsResult.unsafeCoerce()
        this.Nx = this.ops.config.hashLen
    }

    async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
        if (salt.length === 0) {
            salt = new Uint8Array(this.Nx)
        }
        const result = await this.ops.extract(salt)(ikm)
        if (result.isLeft()) {
            throw result.unsafeCoerce()
        }
        return result.unsafeCoerce()
    }

    async expand(prk: Uint8Array, info: Uint8Array, lenBytes: number): Promise<Uint8Array> {
        const result = await this.ops.expand(prk)(info)(lenBytes)
        if (result.isLeft()) {
            throw result.unsafeCoerce()
        }
        return result.unsafeCoerce()
    }
}

export interface KSFFn {
    readonly name: string
    readonly harden: (input: Uint8Array) => Uint8Array
}

export const IdentityKSFFn: KSFFn = { name: 'Identity', harden: (x) => x } as const

export const ScryptKSFFn: KSFFn = {
    name: 'scrypt',
    harden: (msg: Uint8Array): Uint8Array => scrypt(msg, new Uint8Array(), { N: 32768, r: 8, p: 1 })
} as const

export interface AKEKeyPair {
    private_key: Uint8Array
    public_key: Uint8Array
}

export interface AKEExportKeyPair {
    private_key: number[]
    public_key: number[]
}

export interface AKEFn {
    readonly Nsk: number // Nsk: The size of AKE private keys.
    readonly Npk: number // Npk: The size of AKE public keys.
    deriveDHKeyPair(seed: Uint8Array): Promise<AKEKeyPair>
    generateDHKeyPair(): Promise<AKEKeyPair>
}

export interface OPRFFn {
    readonly Noe: number // Noe: The size of a serialized OPRF group element.
    readonly hash: string // hash: Name of the hash function used.
    readonly id: string // id: Identifier of the OPRF.
    readonly name: string // name: Name of the OPRF function.
    blind(input: Uint8Array): Promise<{ blind: Uint8Array; blindedElement: Uint8Array }>
    evaluate(key: Uint8Array, blinded: Uint8Array): Promise<Uint8Array>
    finalize(input: Uint8Array, blind: Uint8Array, evaluation: Uint8Array): Promise<Uint8Array>
    deriveOPRFKey(seed: Uint8Array): Promise<Uint8Array>
}
