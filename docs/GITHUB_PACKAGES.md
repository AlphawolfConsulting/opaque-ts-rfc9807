# GitHub Packages with pnpm Guide

This guide explains how to publish and consume packages using GitHub Packages with pnpm.

## Overview

GitHub Packages is a software package hosting service integrated with GitHub. It supports npm packages, Docker images, and more. This guide focuses on npm package publishing and consumption.

**Benefits:**

- Free private package hosting for GitHub users
- Integrated with GitHub Actions CI/CD
- No separate npm account needed
- Supports both public and private packages

## Prerequisites

- GitHub account with repository access
- pnpm installed (>= 9.0.0)
- Package with proper `package.json` setup
- GitHub Personal Access Token (PAT) for authentication

## Step 1: Create GitHub Personal Access Token (PAT)

### Generate a new token

1. Go to GitHub Settings → [Developer settings → Personal access tokens](https://github.com/settings/tokens)
2. Click "Generate new token" → "Generate new token (classic)"
3. Give it a descriptive name: `github-packages-token`
4. Select scopes:
   - `write:packages` — Publish packages
   - `read:packages` — Install private packages
   - `delete:packages` — Delete packages (optional)
5. Click "Generate token"
6. **Save the token immediately** — you cannot view it again

Example token format:

```text
ghp_1234567890abcdefghijklmnopqrstuvwxyz
```

## Step 2: Configure pnpm for GitHub Packages

### Option A: Global .npmrc (Recommended)

Create or edit `~/.npmrc`:

```text
@YOUR_GITHUB_USERNAME:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=ghp_YOUR_TOKEN_HERE
```

Replace:

- `YOUR_GITHUB_USERNAME` — Your GitHub username
- `ghp_YOUR_TOKEN_HERE` — Your Personal Access Token

### Option B: Project-level .npmrc

Create `.npmrc` in your project root (add to `.gitignore`):

```text
@YOUR_GITHUB_USERNAME:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

This uses environment variable `GITHUB_TOKEN` for CI/CD automation.

### Option C: GitHub Actions Environment

In `.github/workflows/publish.yml`:

```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

pnpm automatically uses `GITHUB_TOKEN` if available.

## Step 3: Update package.json

Configure your package for GitHub Packages:

```json
{
  "name": "@YOUR_GITHUB_USERNAME/package-name",
  "version": "1.0.0",
  "publishConfig": {
    "registry": "https://npm.pkg.github.com"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/YOUR_GITHUB_USERNAME/repo-name"
  }
}
```

**Important:**

- Package name **must** start with `@YOUR_GITHUB_USERNAME` (scoped package)
- `publishConfig.registry` directs where to publish
- `repository` field is required

## Step 4: Publish a Package

### Build the package

```bash
pnpm build
```

### Publish to GitHub Packages

```bash
pnpm publish
```

Output confirms:

```text
npm notice Publishing to GitHub Packages as @YOUR_USERNAME/package-name@1.0.0
```

Verify on GitHub:

- Go to repository → **Packages** tab
- Your package should appear

### Publish with version bump

Update version first:

```bash
npm version patch      # 1.0.0 → 1.0.1
pnpm publish
```

Or bump and publish in one command:

```bash
pnpm publish --version patch
```

## Step 5: Install from GitHub Packages

### Install as a dependency

In another project's `package.json`:

```json
{
  "dependencies": {
    "@YOUR_GITHUB_USERNAME/package-name": "^1.0.0"
  }
}
```

Ensure that project has pnpm `.npmrc` or `~/.npmrc` configured with GitHub token.

Then install:

```bash
pnpm install
```

### Install directly via CLI

```bash
pnpm add @YOUR_GITHUB_USERNAME/package-name
```

### Install specific version

```bash
pnpm add @YOUR_GITHUB_USERNAME/package-name@1.0.1
```

### Install from git URL (alternative)

```bash
pnpm add github:YOUR_GITHUB_USERNAME/repo-name
```

This installs from the git repository instead of npm registry.

## Step 6: Automate Publishing with GitHub Actions

### Create `.github/workflows/publish.yml`

```yaml
name: Publish to GitHub Packages

on:
  push:
    branches:
      - main
    paths:
      - 'package.json'

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - uses: actions/checkout@v4
      
      - uses: pnpm/action-setup@v2
        with:
          version: 9
      
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: 'pnpm'
      
      - run: pnpm install
      
      - run: pnpm build
      
      - run: pnpm publish
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

This workflow:

- Triggers on pushes to main that modify `package.json`
- Sets up Node 22 and pnpm
- Builds and publishes the package
- Uses GitHub's built-in `GITHUB_TOKEN` (no PAT needed)

## Step 7: Install Private Packages in CI/CD

For GitHub Actions workflows that need to install private packages:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: read

    steps:
      - uses: actions/checkout@v4
      
      - uses: pnpm/action-setup@v2
      
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: 'pnpm'
      
      - run: pnpm install
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

pnpm automatically uses `GITHUB_TOKEN` for authentication.

## Configuration Examples

### .npmrc for multiple registries

If using both npm and GitHub Packages:

```text
# Default registry (npm)
registry=https://registry.npmjs.org/

# GitHub packages (scoped)
@YOUR_USERNAME:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=ghp_YOUR_TOKEN

# Other scoped registries
@OTHER_ORG:registry=https://other-registry.com
```

### Using environment variables in .npmrc

```text
@YOUR_USERNAME:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

Then set `GITHUB_TOKEN` before running pnpm:

```bash
export GITHUB_TOKEN=ghp_your_token_here
pnpm install
```

## Troubleshooting

### 401 Unauthorized when publishing

- Verify PAT has `write:packages` scope
- Check token is not expired
- Ensure `.npmrc` has correct token: `//npm.pkg.github.com/:_authToken=TOKEN`

### 403 Forbidden when publishing

- Package name must start with `@USERNAME` (scoped)
- Verify `publishConfig.registry` is correct: `https://npm.pkg.github.com`
- Check GitHub token permissions

### 404 Not Found when installing

- Verify `.npmrc` registry is configured: `@USERNAME:registry=https://npm.pkg.github.com`
- Ensure you have `read:packages` permission on the PAT
- Check package name is correct (lowercase, scoped)

### pnpm cannot find package

- Run `pnpm cache clean` to clear cache
- Verify GitHub token is set in environment: `echo $GITHUB_TOKEN`
- Check `.npmrc` configuration: `cat ~/.npmrc`

## Best Practices

- [YES] Store PAT in GitHub Secrets, never in code
- [YES] Use scoped packages: `@username/package-name`
- [YES] Use `publishConfig` to specify GitHub registry
- [YES] Automate publishing with GitHub Actions
- [YES] Use `GITHUB_TOKEN` in CI (no PAT needed)
- [NO] Don't commit `.npmrc` with tokens to git
- [NO] Don't use unscoped packages with GitHub Packages
- [NO] Don't reuse PAT across multiple projects

## GitHub Secrets Setup

For GitHub Actions workflows:

1. Go to repository → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `GITHUB_TOKEN_PACKAGES`
4. Value: (PAT with `write:packages` scope)
5. Click **Add secret**

Then use in workflow:

```yaml
- run: pnpm publish
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN_PACKAGES }}
```

**Note:** GitHub automatically provides `secrets.GITHUB_TOKEN` for workflows — use it by default.

## Publishing Checklist

- [x] GitHub PAT created with `write:packages` scope
- [x] `.npmrc` configured with GitHub registry
- [x] Package name is scoped: `@username/name`
- [x] `package.json` has `publishConfig.registry`
- [x] `pnpm build` succeeds
- [x] `pnpm test` passes
- [x] Version bumped in `package.json`
- [x] `pnpm publish` succeeds
- [x] Package visible in repository **Packages** tab

## Reference

- [GitHub Packages npm Documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry)
- [pnpm Configuration](https://pnpm.io/npmrc)
- [GitHub Personal Access Tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
- [GitHub Actions Node Setup](https://github.com/actions/setup-node)
