export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

export interface LogEntry {
    readonly message: string
    readonly [key: string]: unknown
}

/** Implement this interface to provide a custom logger */
export interface OpaqueLogger {
    debug(entry: LogEntry): void
    error(entry: LogEntry): void
}

/** Implement this interface to provide a custom config loader */
export interface OpaqueLoader {
    load(): Record<string, unknown>
}

export interface LogConfig {
    readonly minLevel?: LogLevel
    readonly prefix?: string
}
