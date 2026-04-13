import type { OpaqueLogger, LogEntry, LogConfig, LogLevel } from './types.js'

const LEVELS: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 }

export class DefaultConsoleLogger implements OpaqueLogger {
    private readonly minLevel: LogLevel
    private readonly prefix: string

    constructor(config: LogConfig = {}) {
        this.minLevel = config.minLevel ?? 'info'
        this.prefix = config.prefix ?? 'opaque'
    }

    debug(entry: LogEntry): void {
        this.log('debug', entry)
    }

    error(entry: LogEntry): void {
        this.log('error', entry)
    }

    private log(level: LogLevel, entry: LogEntry): void {
        if (LEVELS[level] < LEVELS[this.minLevel]) return
        const { message, ...meta } = entry
        const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : ''
        const line = `[${this.prefix}] [${level.toUpperCase()}] ${message}${metaStr}`
        level === 'error' ? console.error(line) : console.log(line)
    }
}
