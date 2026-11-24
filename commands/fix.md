---
description: Fix vulnerable dependencies — upgrade to safe versions, then run the tests
argument-hint: "[path] [min severity: low|moderate|high|critical]"
---

Fix the project's vulnerable dependencies using pkgguard.

Arguments: $ARGUMENTS (an optional path and/or minimum severity, as for `/pkgguard:scan`)

1. Call `suggest_fixes` to get the plan. If nothing is vulnerable, say so and stop.
2. Show the plan briefly: which packages change, from and to which version, and which CVEs that resolves. Point out any **major** version jump. If a major jump is needed, ask before doing it.
3. Make a note of the current test result, using the project's own test command.
4. Apply the fixes with the commands from the plan. Prefer upgrading the direct dependency that pulls a vulnerable package in over adding an override. Use the project's own package manager (the one the lockfile belongs to).
5. If the package manager fails, diagnose it instead of forcing it: don't use `--force` or `--legacy-peer-deps` without asking.
6. Run the typecheck/build and the tests again, and compare with step 3.
7. Run `scan_project` again and report what is fixed and what is left.

Do not commit unless the user asks.
