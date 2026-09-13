# Releasing LombokFuzzer

Releases are automated by [`.github/workflows/publish.yml`](./.github/workflows/publish.yml),
which publishes to **two** registries on every GitHub Release:

| Registry | Package name | Auth |
|---|---|---|
| npm (public) | `lombokfuzzer` | `NPM_TOKEN` secret |
| GitHub Packages | `@codinglombok/lombokfuzzer` | built-in `GITHUB_TOKEN` |

The npm package is unscoped; GitHub Packages requires the org scope, so the
workflow renames the package to `@codinglombok/lombokfuzzer` for that step only.

## One-time setup

Add an npm **automation** access token as a repository secret:

1. Create the token at npmjs.com → *Access Tokens* → *Generate New Token* →
   *Automation* (this token type bypasses 2FA in CI).
2. In the repo: *Settings → Secrets and variables → Actions → New repository
   secret*, name it `NPM_TOKEN`.

`GITHUB_TOKEN` is provided automatically — no setup needed for GitHub Packages.
The workflow already requests `packages: write` and `id-token: write`
(the latter enables npm provenance).

## Cutting a release

1. Bump the version in `package.json` (follow semver).
2. Commit and push to `main`: `git commit -am "Release v0.1.1" && git push`.
3. Tag and create a GitHub Release whose tag matches the version, prefixed with
   `v` — e.g. version `0.1.1` → tag `v0.1.1`. Either:
   - **GitHub CLI:** `gh release create v0.1.1 --title "v0.1.1" --generate-notes`, or
   - the *Releases → Draft a new release* UI.
4. Publishing the release triggers the workflow. It re-checks that the tag
   matches `package.json`, builds, tests, then publishes to both registries.

A version mismatch between the tag and `package.json` fails the run before
anything is published, so a mistyped tag can't ship the wrong version.

## Installing

From npm (default):

```bash
npm install lombokfuzzer
```

From GitHub Packages (requires an `.npmrc` mapping the scope):

```
@codinglombok:registry=https://npm.pkg.github.com
```

```bash
npm install @codinglombok/lombokfuzzer
```
