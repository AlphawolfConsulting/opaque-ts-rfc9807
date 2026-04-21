# NPM Publishing Guide

This guide explains how to build, test, and publish `@alphawolfconsulting/opaque-ts-rfc9807` to npm.

## Prerequisites

- Node.js >= 22 (see [Node.js Version Strategy](../llm-context/ProjectStructure.md#nodejs-version-strategy) — always n and n-1 LTS)
- npm account at [npmjs.com](https://www.npmjs.com/)
- Local npm authentication configured

## Step 1: Authenticate with npm

Authenticate with npm to enable publishing:

```bash
npm login
```

Enter your npm username, password, and two-factor authentication code when prompted.

Verify authentication:

```bash
npm whoami
```

## Step 2: Build the Package

Build the TypeScript source to JavaScript:

```bash
pnpm build
```

This generates:

- `lib/src/**/*.js` — Compiled JavaScript
- `lib/src/**/*.d.ts` — TypeScript declarations

Verify the build output exists:

```bash
ls -la lib/src/
```

You should see `.js` and `.d.ts` files matching `src/` structure.

## Step 3: Local Testing (Before Publishing)

### Option A: Using npm link (Symlink Testing)

Test locally by symlinking the package:

```bash
# In the opaque-ts-rfc9807 directory
npm link

# In your test project directory
npm link @alphawolfconsulting/opaque-ts-rfc9807
```

Usage in test project:

```typescript
import { ClientState } from '@alphawolfconsulting/opaque-ts-rfc9807';
// ... test your code
```

When done testing:

```bash
# In test project
npm unlink @alphawolfconsulting/opaque-ts-rfc9807

# In opaque-ts-rfc9807
npm unlink
```

### Option B: Using npm pack (Tarball Testing)

Create a local tarball and test in isolation:

```bash
# In opaque-ts-rfc9807 directory
npm pack
```

This creates `alphawolfconsulting-opaque-ts-rfc9807-1.0.1.tgz` (version may vary).

In your test project:

```bash
npm install /full/path/to/alphawolfconsulting-opaque-ts-rfc9807-1.0.1.tgz
```

Or use relative path:

```bash
npm install ../opaque-ts-rfc9807/alphawolfconsulting-opaque-ts-rfc9807-1.0.1.tgz
```

When done, clean up the tarball:

```bash
rm alphawolfconsulting-opaque-ts-rfc9807-1.0.1.tgz
```

## Step 4: Verify Package Contents

Ensure `files` in package.json is correct:

```bash
npm pack --dry-run
```

Expected output should list:

- All compiled `.js` files from `lib/src/`
- All `.d.ts` type declaration files
- `package.json`
- `README.md`
- `LICENSE` (if present)

Should **NOT** include:

- `src/` (only compiled `lib/` is included)
- `test/` directory
- Node modules
- Config files (unless explicitly in `files`)

## Step 5: Update Version

Before publishing, update the version in `package.json` following [semver](https://semver.org/):

```json
{
  "version": "1.0.2"
}
```

Version guidelines:

- **Patch** (1.0.X) — Bug fixes, backward compatible
- **Minor** (1.X.0) — New features, backward compatible
- **Major** (X.0.0) — Breaking changes

Or use npm version:

```bash
npm version patch    # 1.0.1 → 1.0.2
npm version minor    # 1.0.2 → 1.1.0
npm version major    # 1.1.0 → 2.0.0
```

This updates package.json and creates a git tag.

## Step 6: Publish to npm

Publish the package:

```bash
npm publish
```

Output should confirm:

```text
npm notice 📦 @alphawolfconsulting/opaque-ts-rfc9807@1.0.2
npm notice + 1 file
```

Verify on npm:

Visit: `https://www.npmjs.com/package/@alphawolfconsulting/opaque-ts-rfc9807`

## Step 7: Test Published Package

In a **new directory** (outside your repo):

```bash
mkdir test-install
cd test-install
npm init -y
npm install @alphawolfconsulting/opaque-ts-rfc9807
```

Create a test file:

```typescript
// test.ts
import {
  ClientState,
  ServerState,
  OPAQUEConfig,
} from '@alphawolfconsulting/opaque-ts-rfc9807';

const config = new OPAQUEConfig();
console.log('Import successful:', !!ClientState);
```

Run the test:

```bash
npx tsx test.ts
```

Expected output: `Import successful: true`

## Step 8: Version Verification

Check that your version appears on npm:

```bash
npm view @alphawolfconsulting/opaque-ts-rfc9807 versions
```

Latest version should match what you published:

```bash
npm view @alphawolfconsulting/opaque-ts-rfc9807 version
```

## Troubleshooting

### 403 Forbidden on publish

- Verify npm login: `npm whoami`
- Check package.json `name` matches npm organization
- Ensure `"private": false` in package.json

### Package installed but imports fail

- Verify `main`, `module`, and `types` fields point to correct paths
- Check `files` array includes compiled output
- Run `npm pack --dry-run` to verify contents

### Build failed before publish

Ensure all steps pass:

```bash
pnpm build          # Compilation succeeds
pnpm test           # All tests pass
pnpm lint:publish   # Linting passes
```

### Package named incorrectly

Check npm username:

```bash
npm whoami
```

Package name format:

- Scoped: `@org/package-name`
- Unscoped: `package-name`

Verify in package.json:

```json
{
  "name": "@alphawolfconsulting/opaque-ts-rfc9807"
}
```

## Publishing Checklist

- [x] `npm login` authenticated
- [x] `pnpm build` succeeds
- [x] `pnpm test` passes
- [x] `pnpm lint:publish` passes
- [x] Version updated in package.json
- [x] `npm pack --dry-run` shows correct files
- [x] `npm publish` succeeds
- [x] Package visible on npmjs.com
- [x] Test import in new directory succeeds

## Reference

- [npm Publish Documentation](https://docs.npmjs.com/cli/v9/commands/npm-publish)
- [npm Semver Guide](https://docs.npmjs.com/about/semantic-versioning)
- [Scoped Packages](https://docs.npmjs.com/cli/v9/using-npm/scope)
