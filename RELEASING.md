# Releasing LombokFuzzer

Publishing a GitHub Release fires **two** workflows, which together push to
**six** registries:

| Workflow | Registry | Package name | Auth |
|---|---|---|---|
| `publish.yml` | npm (public) | `lombokfuzzer` | `NPM_TOKEN` secret |
| `publish-packages.yml` | npm (GitHub Packages) | `@codinglombok/lombokfuzzer` | built-in `GITHUB_TOKEN` |
| `publish-packages.yml` | Container (ghcr.io) | `ghcr.io/codinglombok/lombokfuzzer` | built-in `GITHUB_TOKEN` |
| `publish-packages.yml` | Maven (webjar) | `com.github.codinglombok:lombokfuzzer` | built-in `GITHUB_TOKEN` |
| `publish-packages.yml` | NuGet | `codinglombok.LombokFuzzer` | built-in `GITHUB_TOKEN` |
| `publish-packages.yml` | RubyGems | `lombokfuzzer` | built-in `GITHUB_TOKEN` |

Only the public npm package is unscoped; the npm-on-GitHub-Packages entry must
carry the org scope, so `publish-packages.yml` renames it to
`@codinglombok/lombokfuzzer` for that step. The Maven/NuGet/RubyGems entries are
"webjar-style" wrappers — they bundle the built JS `dist` into each platform's
native package format so the ecosystem is present on every registry.

## One-time setup

Only the public npm registry needs a secret. Everything under GitHub Packages
uses the built-in `GITHUB_TOKEN` (no setup).

1. Create an npm **automation** access token at npmjs.com → *Access Tokens* →
   *Generate New Token* → *Automation* (bypasses 2FA in CI).
2. In the repo: *Settings → Secrets and variables → Actions → New repository
   secret*, name it `NPM_TOKEN`.

## Cutting a release

1. Bump the version in `package.json` (follow semver).
2. Commit and push to `main`.
3. Tag and create a GitHub Release whose tag matches the version, prefixed with
   `v` — e.g. version `0.1.1` → tag `v0.1.1`. Either:
   - **GitHub CLI:** `gh release create v0.1.1 --title "v0.1.1" --generate-notes`, or
   - the *Releases → Draft a new release* UI.
4. Publishing the release triggers both workflows: `publish.yml` re-checks that
   the tag matches `package.json`, then publishes to npmjs.org;
   `publish-packages.yml` builds once and fans out to the five GitHub Packages
   registries.

A tag/`package.json` version mismatch fails `publish.yml` before anything ships.

## Installing

Public npm (default):

```bash
npm install lombokfuzzer
```

From GitHub Packages (requires an `.npmrc` mapping the scope to GitHub):

```
@codinglombok:registry=https://npm.pkg.github.com
```

```bash
npm install @codinglombok/lombokfuzzer
```
