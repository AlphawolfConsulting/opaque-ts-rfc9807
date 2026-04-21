# Functional Programming Guidelines for OPAQUE RFC 9807

## Core Principles

1. **Pure Functions by Default**: Functions should be pure unless absolutely necessary
2. **Explicit Side Effects**: Side effects must be clearly documented
3. **Immutability**: Data structures should be immutable
4. **Composition Over Inheritance**: Prefer function composition
5. **Currying for Partial Application**: Use currying for configuration functions

## Side Effect Rules

### Allowed Side Effects (Maximum 1-2 per function)

1. **Crypto Operations**: `crypto.subtle`, `crypto.getRandomValues()`
2. **Logging**: Using `@zambit/logging-lite` logger
3. **Network I/O**: Using `@zambit/prioritized-loader-lite` loader

**Note on IDs**:

- **Cryptographic IDs** (nonces, seeds): MUST use `crypto.getRandomValues()`
- **Tracking IDs** (for logging, sessions): Can optionally use cuid2
- **NEVER** use cuid2, UUID, or any non-CSPRNG for cryptographic material

### Side Effect Tracking Pattern

Mark functions with side effects in JSDoc:

```typescript
/**
 * Generates a random nonce for envelope creation
 * @sideEffect Crypto RNG
 * @returns {Uint8Array} Random nonce of Nn bytes
 */
const generateNonce = (Nn: number): Uint8Array => {
    // SIDE EFFECT: crypto.getRandomValues()
    return crypto.getRandomValues(new Uint8Array(Nn))
}
```

## Currying Patterns

### When to Use Currying

1. **Configuration Functions**: Partial application of config parameters
2. **Cryptographic Operations**: Pre-configure hash/MAC functions
3. **Validation Functions**: Partial application of constraints

### Example Pattern

```typescript
// Curry the Expand function with config
const createExpand = (config: Config) =>
    (prk: Uint8Array) =>
    (info: readonly number[], length: number): Promise<Uint8Array> =>
        config.KDF.expand(prk, new Uint8Array(info), length)

// Usage
const expand = createExpand(config)
const expandWithPrk = expand(prk)
const maskingKey = await expandWithPrk(LABELS.MaskingKey, Nh)
```

## Error Handling with Monads

### Using Either for Error Handling

```typescript
import { Either, Right, Left } from 'purify-ts'

const safeParseInt = (str: string): Either<Error, number> => {
    const num = parseInt(str, 10)
    return isNaN(num) ? Left(new Error('Invalid number')) : Right(num)
}

// Chain operations
const result = safeParseInt('42')
    .map((n) => n * 2)
    .chain((n) => (n > 0 ? Right(n) : Left(new Error('Must be positive'))))
```

### Using Maybe for Optional Values

```typescript
import { Maybe, Just, Nothing } from 'purify-ts'

const findUser = (id: string): Maybe<User> =>
    users.has(id) ? Just(users.get(id)) : Nothing
```

## Function Composition

### Pipe Pattern

```typescript
const processPassword = pipe(normalizePassword, hashPassword, saltPassword)

const result = processPassword(rawPassword)
```

### Async Pipe Pattern

```typescript
const processCredential = pipeAsync(blindPassword, evaluateOprf, finalizeOprf)

const credential = await processCredential(password)
```

## Testing Pure Functions

Pure functions are easy to test:

```typescript
describe('deriveKey', () => {
    it('should produce same output for same input', () => {
        const input = new Uint8Array([1, 2, 3])
        const result1 = deriveKey(input)
        const result2 = deriveKey(input)
        expect(result1).toEqual(result2)
    })
})
```

## Migration Checklist

- [ ] Identify all side effects in existing code
- [ ] Mark side effects with JSDoc comments
- [ ] Ensure no function has more than 2 side effects
- [ ] Convert Result<T, E> to Either<E, T> where beneficial
- [ ] Apply currying to configuration functions
- [ ] Use Maybe for optional values
- [ ] Add functional tests for pure functions
