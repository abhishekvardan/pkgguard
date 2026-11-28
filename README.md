# pkgguard

pkgguard is a Claude Code plugin that tells Claude which package versions in your project have known vulnerabilities, and warns Claude before it installs one. It also comes with:

- a **guarded package manager** (`pkgguard add` / `pkgguard install`) that won't install a vulnerable version, for you and for CI;
- an **always-on watcher** that notices when an advisory is published against a version you *already* have, notifies you, and makes the next Claude session lead with it. You don't have to hear about it from Reddit first.

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

## Guarded installs

Use `pkgguard add` where you would use `npm install <pkg>`, `pnpm add`, `yarn add`, `bun add`, `pip install`, `uv add`, `poetry add`, `pipenv install`, `cargo add`, `go get`, `bundle add`, `composer require` or `dotnet add package`. pkgguard picks the project's own manager from its lockfile.

```text
$ pkgguard add lodash@4.17.15 left-pad
pkgguard: lodash@4.17.15 has 5 known vulnerabilities [high], e.g. GHSA-r5fr-rjxr-66jc (CVE-2026-4800) …
  → installing lodash@4.18.1 instead.
pkgguard: left-pad@1.3.0: no known vulnerabilities.
pkgguard: npm install lodash@4.18.1 left-pad
added 2 packages in 4s
pkgguard: ✓ the install added no known vulnerabilities.
```

- A vulnerable version is swapped for the nearest safe one. When no fixed version exists, nothing is installed (exit 2) unless you pass `--allow-vulnerable`.
- After installing, pkgguard rescans and reports vulnerable packages that came in **transitively**. With `--strict` it puts `package.json` and the lockfile back exactly as they were and exits 2. This is the mode for scripts and CI.
- Other options: `-D` for dev dependencies, `--dry-run` to only show the command, `--pm pnpm` to override the detected manager. Arguments after `--` go to the package manager unchanged.

`pkgguard install [--ci]` installs from the lockfile. It **refuses before downloading anything** when the lockfile pins vulnerabilities at or above `failOn` (default `high`). `--ci` uses the frozen-lockfile mode: `npm ci`, `pnpm install --frozen-lockfile`, `uv sync --locked`, and so on.

## Always-on watcher

```bash
pkgguard watch "~/code"                                   # report what's NEW since the last run
pkgguard schedule install --every 6h "~/code" "~/work"    # run it on a timer, with notifications
pkgguard schedule status | run | remove
```

- `watch` finds every project under the folders: git repositories, or folders with a dependency file, up to 3 levels deep. It scans each one and keeps per-project state in `~/.pkgguard/state.json`.
  - The first run records a baseline. Later runs list only what is **new** and what was **resolved**.
  - Most new findings are advisories published against versions you already had. No install or edit would ever surface those.
  - It exits 1 when something new reaches the threshold.
- `--notify` (always on for the schedule) shows a desktop notification: a Windows toast, macOS Notification Center, or `notify-send` on Linux.
- **The next Claude session knows too.** At session start pkgguard leads with "NEW since the last session: …", and Claude mentions it in its first reply and offers to fix it.
- `schedule install` creates a Windows Task Scheduler task for your user. It runs hidden while you are signed in and logs to `~/.pkgguard/watch.log`. On macOS and Linux it prints the crontab line to add.

Fixing stays your call: ask Claude, or run `/pkgguard:fix`.

## Policy: `.pkgguard.json`

Put this in a repository root (pkgguard also looks in parent folders, up to the repository root):

```json
{
  "minSeverity": "moderate",
  "failOn": "high",
  "ignore": [
    { "id": "CVE-2021-44906", "package": "minimist", "reason": "only used by a build script", "until": "2027-06-30" }
  ]
}
```

| Field | Meaning |
|---|---|
| `minSeverity` | Threshold for the install and edit warnings and the watcher (default `moderate`) |
| `failOn` | Lowest severity that fails `pkgguard scan`, blocks `pkgguard install`, and decides `--strict` (scan default: any; install default: `high`) |
| `ignore` | Accepted risks, by advisory ID or alias. `package` narrows an entry to one package. After `until`, the ignore stops applying and pkgguard says so, so accepted risks get revisited. |

`pkgguard scan --baseline base.json` (where `base.json` comes from an earlier `scan --json`) reports and fails only on findings that are **new** compared with that scan. Use it in CI to fail a PR only when the PR itself introduces a vulnerability.

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
| `PKGGUARD_MCP_MAX_CHARS` | `20000` | Size cap for each tool result. Big scans show the most severe packages and a count of the rest |
| `PKGGUARD_CACHE_DIR` | `~/.cache/pkgguard` | OSV answers are cached 6–24 h, so repeat scans take about a second |
| `PKGGUARD_FAIL_ON` | policy `failOn` | Overrides `failOn` for `scan` and `install` |
| `PKGGUARD_STATE_DIR` | `~/.pkgguard` | Watcher state, the scheduled task's scripts, and `watch.log` |
| `PKGGUARD_NO_STATE` | unset | Set to `1` so session starts don't read or write the watcher state |
| `PKGGUARD_NO_NOTIFY` | unset | Set to `1` to silence desktop notifications |

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
