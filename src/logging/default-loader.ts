import type { OpaqueLoader } from './types.js'

export class DefaultEnvLoader implements OpaqueLoader {
    constructor(private readonly envKey = 'OPAQUE_CONFIG') {}

    load(): Record<string, unknown> {
        try {
            const raw = (typeof process !== 'undefined' && process.env[this.envKey]) || '{}'
            return JSON.parse(raw) as Record<string, unknown>
        } catch {
            return {}
        }
    }
}
