# OPRF Dependency Audit Report

**Date**: February 6, 2026  
**Package**: @cloudflare/voprf-ts  
**Audit Purpose**: Verify RFC 9497 compliance for OPAQUE RFC 9807 upgrade

---

## Current Status

### Installed Version

- **Current**: `0.21.2`
- **Latest Available**: `1.0.0`
- **Status**: ⚠️ UPGRADE REQUIRED

### Available Versions

```text
0.8.0
0.9.0
0.11.0
0.21.2  ← Current
1.0.0   ← Latest (RFC 9497 compliant)
```

---

## RFC 9497 Compliance Analysis

### Version 1.0.0 (Released August 13, 2024)

**Official Release Notes**:
> "Fully compatible with [RFC 9497](https://www.rfc-editor.org/info/rfc9497)"

**Key Features**:

- ✅ RFC 9497 fully compliant
- ✅ Support for Decaf & Ristretto groups
- ✅ Support for noble cryptography backend
- ✅ Exposes DLEQParams static methods
- ✅ Improved type declarations
- ✅ Security vulnerability fixes

**API Changes from 0.21.2 → 1.0.0**:

- Introduced `@cloudflare/voprf-ts/facade` for flexible crypto provider
- Pass crypto as argument everywhere for better testability
- Improved import type declarations
- Updated dependencies and fixed security issues

---

## Recommendation

### ✅ UPGRADE TO 1.0.0

**Rationale**:

1. **RFC 9497 Compliance**: Version 1.0.0 is officially RFC 9497 compliant
2. **OPAQUE RFC 9807 Requirement**: OPAQUE RFC 9807 depends on RFC 9497 OPRF
3. **Active Maintenance**: Recent release (Aug 2024) with security fixes
4. **No Breaking Changes**: API is backward compatible with proper imports

### Upgrade Command

```bash
pnpm update @cloudflare/voprf-ts@1.0.0
```

---

## Dependency Information

### Repository

- **GitHub**: <https://github.com/cloudflare/voprf-ts>
- **NPM**: <https://www.npmjs.com/package/@cloudflare/voprf-ts>
- **License**: BSD-3-Clause
- **Maintainer**: Cloudflare (armfazh, thibmeu, and team)

### Supported Modes

- `Oprf.Mode.OPRF` - Base OPRF (used by OPAQUE)
- `Oprf.Mode.VOPRF` - Verifiable OPRF
- `Oprf.Mode.POPRF` - Partially-Oblivious OPRF

### Supported Suites (with Noble backend)

- ✅ `Oprf.Suite.P256_SHA256`
- ✅ `Oprf.Suite.P384_SHA384`
- ✅ `Oprf.Suite.P521_SHA512`
- ✅ `Oprf.Suite.RISTRETTO255_SHA512`
- ✅ `Oprf.Suite.DECAF448_SHAKE256`

---

## API Changes Impact Assessment

### Current OPAQUE Usage Pattern

```typescript
import { OPRFClient, OPRFServer, Oprf } from '@cloudflare/voprf-ts'

const client = new OPRFClient(suiteId)
const server = new OPRFServer(suiteId, privateKey)
```

### v1.0.0 Compatibility

- ✅ **No changes required** - Existing API remains compatible
- ✅ Default crypto provider continues to work
- ℹ️ Optional: Can migrate to facade pattern for custom crypto providers

### Migration Risk

- **Risk Level**: LOW
- **Breaking Changes**: None for standard usage
- **Testing Required**: Verify OPRF operations still work correctly
- **Rollback**: Easy (downgrade package version)

---

## Testing Strategy

### Pre-Upgrade Tests

1. ✅ Run current test suite with 0.21.2
2. ✅ Document current behavior

### Post-Upgrade Tests

1. Run existing OPRF tests with 1.0.0
2. Verify blind/evaluate/finalize operations
3. Verify key derivation works correctly
4. Run full OPAQUE registration/authentication flows
5. Verify serialization format unchanged

### Validation Checklist

- [ ] OPRF blind operation works
- [ ] OPRF evaluate operation works
- [ ] OPRF finalize operation works
- [ ] Key derivation produces valid keys
- [ ] All existing tests pass
- [ ] No unexpected type errors
- [ ] Serialized outputs match expected format

---

## RFC 9497 Specification Details

### Key Differences from draft-voprf-08

#### Mode Specification

- **draft-08**: Implicit mode selection
- **RFC 9497**: Explicit mode byte (0x00 for base OPRF)

#### Suite IDs

- Formalized suite identifiers
- Hash-to-curve aligned with RFC 9380

#### API Refinements

- `DeriveKeyPair` formalized in Section 3.2
- Group element serialization standardized

### OPAQUE Integration Points

1. **Registration**: Client blinds password, server evaluates
2. **Authentication**: Same OPRF flow for credential retrieval
3. **Key Derivation**: Server OPRF keys derived via `DeriveKeyPair`

---

## Security Considerations

### From RFC 9497 Section 7

1. **OPRF Key Security**
   - Keys MUST be derived from cryptographically secure random seeds
   - Keys MUST NOT be reused across different contexts

2. **Blinding Randomness**
   - Client MUST use cryptographically secure RNG for blinding
   - voprf-ts uses Web Crypto API `crypto.getRandomValues()`

3. **Timing Attack Resistance**
   - voprf-ts uses constant-time operations where possible
   - Note: JavaScript cannot guarantee constant-time execution

4. **Side Channel Protection**
   - Provider uses [@noble/curves](https://www.npmjs.com/package/@noble/curves) (constant-time aware)
   - Alternative: sjcl (Stanford JavaScript Crypto Library)

---

## Action Items

### Immediate (Phase 1)

- [x] Audit @cloudflare/voprf-ts versions
- [x] Identify RFC 9497 compliant version
- [x] Document API changes and impacts
- [ ] Update package.json to 1.0.0
- [ ] Run tests to verify compatibility
- [ ] Update OPRF wrapper to use RFC 9497 terminology

### Future (Post-Phase 1)

- [ ] Consider facade pattern for custom crypto providers
- [ ] Add RFC 9497 test vectors to test suite
- [ ] Document mode byte (0x00) in OPRF operations

---

## References

- [RFC 9497](https://www.rfc-editor.org/info/rfc9497) - Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups
- [voprf-ts 1.0.0 Release](https://github.com/cloudflare/voprf-ts/releases/tag/1.0.0)
- [voprf-ts Repository](https://github.com/cloudflare/voprf-ts)
- [RFC 9380](https://www.rfc-editor.org/info/rfc9380) - Hash-to-Curve
- [RFC 9807](https://www.rfc-editor.org/info/rfc9807) - OPAQUE

---

## Conclusion

**Verdict**: ✅ **PROCEED WITH UPGRADE**

The @cloudflare/voprf-ts library version 1.0.0 is fully compliant with RFC 9497 and ready for use in the OPAQUE RFC 9807 implementation. The upgrade path is low-risk with no breaking API changes for standard usage patterns.

**Next Step**: Update package.json and proceed with Phase 1 OPRF functional wrapper implementation.
