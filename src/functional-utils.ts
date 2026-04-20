import { Either, Left, Right, Maybe, Just, Nothing } from 'purify-ts'
import type { Result } from './common.js'

// Type aliases for clarity
export type AsyncResult<T, E = Error> = Promise<Either<E, T>>
export type SyncResult<T, E = Error> = Either<E, T>

// Convert Result<T, E> to Either<E, T>
export const resultToEither = <T, E>(result: Result<T, E>): Either<E, T> =>
    result.ok ? Right(result.value) : Left(result.error)

// Convert Either<E, T> to Result<T, E>
export const eitherToResult = <T, E>(either: Either<E, T>): Result<T, E> =>
    either.isRight()
        ? { ok: true, value: either.extract() }
        : { ok: false, error: either.extract() as E }

// Curry helper for 2 arguments
export const curry2 =
    <A, B, C>(fn: (a: A, b: B) => C) =>
    (a: A) =>
    (b: B): C =>
        fn(a, b)

// Curry helper for 3 arguments
export const curry3 =
    <A, B, C, D>(fn: (a: A, b: B, c: C) => D) =>
    (a: A) =>
    (b: B) =>
    (c: C): D =>
        fn(a, b, c)

// Curry helper for 4 arguments
export const curry4 =
    <A, B, C, D, E>(fn: (a: A, b: B, c: C, d: D) => E) =>
    (a: A) =>
    (b: B) =>
    (c: C) =>
    (d: D): E =>
        fn(a, b, c, d)

// Curry helper for 5 arguments
export const curry5 =
    <A, B, C, D, E, F>(fn: (a: A, b: B, c: C, d: D, e: E) => F) =>
    (a: A) =>
    (b: B) =>
    (c: C) =>
    (d: D) =>
    (e: E): F =>
        fn(a, b, c, d, e)

// Curry helper for 6 arguments
export const curry6 =
    <A, B, C, D, E, F, G>(fn: (a: A, b: B, c: C, d: D, e: E, f: F) => G) =>
    (a: A) =>
    (b: B) =>
    (c: C) =>
    (d: D) =>
    (e: E) =>
    (f: F): G =>
        fn(a, b, c, d, e, f)

// Curry helper for 7 arguments
export const curry7 =
    <A, B, C, D, E, F, G, H>(fn: (a: A, b: B, c: C, d: D, e: E, f: F, g: G) => H) =>
    (a: A) =>
    (b: B) =>
    (c: C) =>
    (d: D) =>
    (e: E) =>
    (f: F) =>
    (g: G): H =>
        fn(a, b, c, d, e, f, g)

// Curry helper for 8 arguments
export const curry8 =
    <A, B, C, D, E, F, G, H, I>(fn: (a: A, b: B, c: C, d: D, e: E, f: F, g: G, h: H) => I) =>
    (a: A) =>
    (b: B) =>
    (c: C) =>
    (d: D) =>
    (e: E) =>
    (f: F) =>
    (g: G) =>
    (h: H): I =>
        fn(a, b, c, d, e, f, g, h)

// Pipe function for composition
export const pipe =
    <T>(...fns: ReadonlyArray<(arg: T) => T>) =>
    (value: T): T =>
        fns.reduce((acc, fn) => fn(acc), value)

// Async pipe for promises
export const pipeAsync =
    <T>(...fns: ReadonlyArray<(arg: T) => Promise<T>>) =>
    async (value: T): Promise<T> => {
        let result = value
        for (const fn of fns) {
            result = await fn(result)
        }
        return result
    }

// Try-catch wrapper returning Either
export const tryCatch = <T, E = Error>(
    fn: () => T,
    onError: (e: unknown) => E = (e) => e as E
): Either<E, T> => {
    try {
        return Right(fn())
    } catch (e) {
        return Left(onError(e))
    }
}

// Async try-catch wrapper
export const tryCatchAsync = async <T, E = Error>(
    fn: () => Promise<T>,
    onError: (e: unknown) => E = (e) => e as E
): AsyncResult<T, E> => {
    try {
        return Right(await fn())
    } catch (e) {
        return Left(onError(e))
    }
}

// Memoization helper (pure function caching)
export const memoize = <A extends readonly unknown[], R>(
    fn: (...args: A) => R
): ((...args: A) => R) => {
    const cache = new Map<string, R>()
    return (...args: A): R => {
        const key = JSON.stringify(args)
        const cached = cache.get(key)
        if (cached !== undefined) {
            return cached
        }
        const result = fn(...args)
        cache.set(key, result)
        return result
    }
}

// Async memoization
export const memoizeAsync = <A extends readonly unknown[], R>(
    fn: (...args: A) => Promise<R>
): ((...args: A) => Promise<R>) => {
    const cache = new Map<string, Promise<R>>()
    return async (...args: A): Promise<R> => {
        const key = JSON.stringify(args)
        const cached = cache.get(key)
        if (cached !== undefined) {
            return cached
        }
        const promise = fn(...args)
        cache.set(key, promise)
        return promise
    }
}

// Safe array access returning Maybe
export const safeArrayGet = <T>(arr: readonly T[], index: number): Maybe<T> =>
    index >= 0 && index < arr.length ? Just(arr[index]) : Nothing

// Safe object property access
export const safeProp = <T extends object, K extends keyof T>(obj: T, key: K): Maybe<T[K]> =>
    key in obj ? Just(obj[key]) : Nothing

export { Either, Left, Right, Maybe, Just, Nothing }
