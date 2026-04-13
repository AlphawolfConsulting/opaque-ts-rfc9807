import { DefaultConsoleLogger, DefaultEnvLoader } from './logging/index.js'
import type { OpaqueLogger, OpaqueLoader } from './logging/index.js'

const minLevel = ((typeof process !== 'undefined' && process?.env?.LOG_LEVEL) || 'info') as 'debug' | 'info' | 'warn' | 'error'

// Default instances — swap these out with any OpaqueLogger/OpaqueLoader compliant implementation
export const opaqueLogger: OpaqueLogger = new DefaultConsoleLogger({
    minLevel,
    prefix: 'opaque-rfc9807'
})

export const opaqueLoader: OpaqueLoader = new DefaultEnvLoader('OPAQUE_CONFIG')

// Legacy aliases
export const logger = opaqueLogger
export const loader = opaqueLoader
