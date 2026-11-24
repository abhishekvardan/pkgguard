---
description: Scan this project's dependencies for known vulnerabilities (OSV.dev)
argument-hint: "[path] [min severity: low|moderate|high|critical]"
---

Scan the project for vulnerable dependencies with the pkgguard `scan_project` tool.

Arguments: $ARGUMENTS
- A path in the arguments is the directory to scan (default: the current project).
- A severity word (low, moderate, high or critical) is the `min_severity`.

Report the results as a short table: package, version, severity, CVE/GHSA, how it is pulled in (direct, or via which package), dev-only or not, and the safe version. Put critical and high first. Mention any notes the scan returns, such as packages that could not be checked.

Do not change any files. Finish by offering to run `/pkgguard:fix`.
