# pkgguard

pkgguard is a Claude Code plugin that tells Claude which package versions in your project have known vulnerabilities, and warns Claude before it installs one.

It reads your lockfiles, checks each exact version against [OSV.dev](https://osv.dev), and gives Claude the CVE, its severity, how the package got into your project, and the smallest upgrade that fixes it. OSV.dev collects the GitHub Advisory Database, PyPA, RustSec, the Go vulndb, RubySec and more. It is free and needs no API key.

| Ecosystem | Files read |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml` (v5–v9), `yarn.lock` (classic and berry), `package.json` exact pins |
| PyPI | `requirements*.txt` (`==` pins, pip-compile `# via`), `poetry.lock`, `uv.lock`, `Pipfile.lock` |
| Go | `go.mod` (with `replace`) |
| crates.io | `Cargo.lock` |
| RubyGems | `Gemfile.lock` |
| Packagist | `composer.lock` |
| NuGet | `packages.lock.json`, `*.csproj`, `Directory.Packages.props` |
| Maven | `pom.xml` (direct dependencies, `${properties}`), `gradle.lockfile` |

## What Claude gets

**MCP tools** (all read-only):

- `scan_project`: every vulnerable dependency, with severity, CVE/GHSA IDs, whether it is direct or pulled in by another package (and by which), and a verified safe version.
- `check_package`: is `name@version` affected? Without a version, it lists every advisory with its affected ranges and says whether the latest release is clean.
- `suggest_fixes`: the exact command per package manager, such as `npm install x@^1.2.6`, npm `overrides` for transitive packages, `cargo update -p x --precise`, `go get`, or `uv add`.
- `get_vulnerability`: details for a GHSA, CVE, PYSEC, RUSTSEC or GO ID.

**Hooks** (automatic; on any error or timeout they skip silently and never block your work):

- **Session start:** if the project has high or critical vulnerabilities, Claude gets a short summary.
- **Before an install:** when Claude runs `npm i`, `pnpm add`, `yarn add`, `pip install` (including `-r file`), `uv add`, `poetry add`, `cargo add`, `go get`, `gem install`, `bundle add`, `composer require` or `dotnet add package` and the resolved version is vulnerable, you get a permission prompt with the CVE. Claude is told the safe version to use instead. Unpinned installs are resolved to what the registry would actually install.
- **After edits and installs:** if an edit to a manifest, or an install or update command, introduces a vulnerable version, Claude is told.

A **skill** teaches Claude to check before it adds dependencies, to prefer the smallest safe upgrade, and to explain CVEs briefly.

## Install

```text
/plugin marketplace add abhishekvardan/pkgguard
/plugin install pkgguard@pkgguard
```

Start a new session after installing; hooks load at session start.

## Using it

**Automatic (nothing to type):** at session start Claude is told about high and critical problems. Before any install, a vulnerable version triggers a prompt. After edits and installs, Claude is warned about newly introduced vulnerable versions. pkgguard **finds and warns** automatically, but never changes your dependencies on its own. Fixing is always a step you ask for.

**Slash commands:**

| Command | What it does |
|---|---|
| `/pkgguard:scan` | Table of every vulnerable dependency, with CVE, severity, how it got in, and the safe version. Changes nothing. |
| `/pkgguard:scan high` | Only high and critical. A path also works, e.g. `/pkgguard:scan packages/api`. |
| `/pkgguard:fix` | Upgrades to safe versions, runs your tests before and after, re-scans, and asks before any major-version jump. Doesn't commit. |

**Or just ask:** "are my dependencies safe?", "is axios 0.21.0 vulnerable?", "what is CVE-2021-44228?", "fix the critical vulnerabilities", "add express, but a version with no CVEs".

The plugin runs the bundled `dist/` with Node 20 or later. There is no `npm install` step and no `npx` on each start.

You can also run pkgguard without the plugin:

```bash
npx @abhishekvardanbotta/pkgguard scan .            # exits 1 when something is found (works in CI)
npx @abhishekvardanbotta/pkgguard check npm lodash 4.17.15
npx @abhishekvardanbotta/pkgguard vuln CVE-2021-44906
claude mcp add pkgguard -- npx -y @abhishekvardanbotta/pkgguard mcp   # MCP server only
```

## Settings

Set these as environment variables, for example in the `env` block of `.claude/settings.json`.

| Variable | Default | |
|---|---|---|
| `PKGGUARD_HOOK_MODE` | `ask` | Before a vulnerable install: `ask` (prompt you and tell Claude), `deny` (block it and tell Claude why), `warn` (only tell Claude) |
| `PKGGUARD_MIN_SEVERITY` | `moderate` | Threshold for install and edit warnings |
| `PKGGUARD_SESSION_MIN_SEVERITY` | `high` | Threshold for the session-start summary |
| `PKGGUARD_DISABLE` | unset | Set to `1` to turn the hooks off |
| `PKGGUARD_CACHE_DIR` | `~/.cache/pkgguard` | OSV answers are cached 6–24 h, so repeat scans take about a second |

## Limits

- Only exact versions are checked. A manifest with ranges and no lockfile is reported as "not checked".
- Maven `pom.xml` covers direct dependencies only. Add `gradle.lockfile`, or resolve your dependencies, to cover transitive ones.
- "No known vulnerabilities" means OSV has no record of one. It does not prove a package is safe.
- Package names and versions are sent to api.osv.dev and to the public registries (for "latest" lookups). Nothing else leaves your machine.

## Development

```bash
npm install
npm run build     # dist/ is committed: the plugin runs it directly
npm test          # parser, version, CVSS and command-parsing tests (offline)
npm run smoke     # live end-to-end: MCP over stdio and every hook event
```

MIT © Abhishek Vardan Botta
