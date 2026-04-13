export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

export interface LogEntry {
    message: string
    [key: string]: unknown
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
    minLevel?: LogLevel
    prefix?: string
}
