---
name: pkgguard
description: Check dependencies for known vulnerabilities (CVE/GHSA via OSV.dev) with the pkgguard MCP tools. Use before adding, upgrading or pinning any package (npm, pip/PyPI, Go, Cargo, RubyGems, Composer, NuGet, Maven); when the user asks about security, audits, CVEs or vulnerable/outdated dependencies; and when a pkgguard hook message reports a vulnerable version.
---

# pkgguard

pkgguard reads the project's lockfiles and asks OSV.dev (GitHub Advisory Database, PyPA, RustSec, Go vulndb, RubySec and more) which of the exact versions in use have known vulnerabilities.

## Tools

| Tool | Use it when |
|---|---|
| `check_package` (ecosystem, name, version?) | **Before** adding, upgrading or pinning a dependency. Without `version` it lists every advisory with its affected ranges and says whether the latest release is clean. |
| `scan_project` (path?, include_dev?, min_severity?) | The user asks "are my dependencies safe?", "audit", "any CVEs?", or before a release. |
| `suggest_fixes` (path?, min_severity?) | You are about to fix vulnerable dependencies — it gives the safe version and the exact command per package manager. |
| `get_vulnerability` (id) | The user asks what a CVE/GHSA means or how severe it is. |

Ecosystem names: `npm`, `PyPI`, `Go`, `crates.io`, `Maven` (name `group:artifact`), `RubyGems`, `Packagist` (`vendor/package`), `NuGet`. Aliases such as `pip`, `cargo`, `gem`, `composer` work too.

## Rules

1. **Never introduce a version pkgguard reports as vulnerable.** When writing an install command or pinning a version, check it first, or pick the version `check_package` says is clean.
2. **Prefer the smallest safe upgrade.** Use the reported safe version, which stays on the same major line when a backported fix exists. Only jump a major version when no fix exists on the current line, and tell the user it is a major upgrade.
3. **Transitive dependencies:** upgrade the direct dependency that pulls the package in (the `via` chain shows which one), or use the override mechanism `suggest_fixes` prints: npm `overrides`, pnpm `pnpm.overrides`, yarn `resolutions`, `cargo update --precise`, or `go get`.
4. **Explain briefly.** Name the CVE/GHSA ID, its severity and one line on the impact. Don't paste whole advisories.
5. **Hook messages are real.** A pkgguard message before an install means the requested version is vulnerable. Switch to the safe version unless the user explicitly needs that exact one, and if they do, make sure they have seen the warning.
6. After fixing, run the project's tests and then `scan_project` again to confirm.
7. **"NEW since the last session" at session start** means advisories were published (or vulnerable versions arrived) since the user last worked here, and nobody has been told yet. Mention them at the start of your first reply and offer to fix them.
8. **Respect `.pkgguard.json`.** Advisories it ignores were accepted on purpose; don't re-raise them. Don't add an ignore yourself unless the user asks, and always give it a `reason` and an `until` date.
9. **Guarded installs:** if the `pkgguard` CLI is on PATH, `pkgguard add <pkg>` (instead of `npm install` / `pip install` / `cargo add`…) checks and picks a safe version for you, and `pkgguard install` refuses a lockfile with high+ vulnerabilities.
10. "No known vulnerabilities" means OSV has no record. It does not prove a package is safe. Packages with no lockfile entry (ranges in a manifest) are not checked, and the scan notes say so.
