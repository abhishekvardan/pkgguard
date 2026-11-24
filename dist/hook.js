import { basename, isAbsolute, resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { cacheGet, cacheSet } from './core/cache.js';
import { fixCommand } from './core/fix.js';
import { latestVersion, npmResolve } from './core/registry.js';
import { parseSeverity } from './core/severity.js';
import { advisoryTitle, countBySeverity, formatBrief } from './format.js';
import { parseInstallCommand } from './installSpec.js';
import { isDependencyFile, parseFile } from './parsers/detect.js';
import { parsePackageJsonOnly } from './parsers/npm.js';
import { parseRequirements } from './parsers/python.js';
import { checkDeps, filterFindings, scanProject } from './scan.js';
/**
 * Claude Code hook entrypoint (`pkgguard hook`). Reads the event JSON on stdin and prints
 * at most one JSON object on stdout. It fails open: any error, timeout or network problem
 * means no output, so it can never block work by accident.
 */
const NET = { timeoutMs: Number(process.env.PKGGUARD_NET_TIMEOUT_MS) || 5000, retries: 0 };
const SEEN_TTL = 30 * 24 * 60 * 60 * 1000;
function env() {
    const mode = (process.env.PKGGUARD_HOOK_MODE ?? 'ask').toLowerCase();
    return {
        mode: (['ask', 'deny', 'warn'].includes(mode) ? mode : 'ask'),
        min: parseSeverity(process.env.PKGGUARD_MIN_SEVERITY, 'moderate'),
        sessionMin: parseSeverity(process.env.PKGGUARD_SESSION_MIN_SEVERITY, 'high'),
    };
}
const MANAGER_TOOL = {
    npm: 'npm', pnpm: 'pnpm', yarn: 'yarn', bun: 'npm',
    pip: 'pip', uv: 'uv', poetry: 'poetry', pdm: 'pip', rye: 'pip', pipenv: 'pipenv', pipx: 'pip',
    cargo: 'cargo', go: 'go', gem: 'bundler', bundle: 'bundler', composer: 'composer', dotnet: 'nuget',
};
async function resolveIntent(i) {
    if (i.kind === 'exact')
        return i.version;
    if (i.kind === 'latest')
        return latestVersion(i.ecosystem, i.name, NET);
    if (i.ecosystem === 'npm' && i.version)
        return npmResolve(i.name, i.version, NET);
    return undefined;
}
// ---------- "seen" set: report each vulnerable package once per project ----------
const keyOf = (f) => `${f.dep.ecosystem}|${f.dep.name}|${f.dep.version}`;
function seenGet(root) {
    return new Set(cacheGet(`seen|${root.toLowerCase()}`, SEEN_TTL) ?? []);
}
function seenAdd(root, findings) {
    const s = seenGet(root);
    findings.forEach((f) => s.add(keyOf(f)));
    cacheSet(`seen|${root.toLowerCase()}`, [...s].slice(-5000));
}
let result;
function out(obj) {
    result = JSON.stringify(obj);
}
function projectRoot(input) {
    return process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd();
}
async function preToolUse(input) {
    if (input.tool_name !== 'Bash')
        return;
    const command = String(input.tool_input?.command ?? '');
    const parsed = parseInstallCommand(command);
    if (!parsed.intents.length && !parsed.requirementFiles.length)
        return;
    const { mode, min } = env();
    const cwd = input.cwd || projectRoot(input);
    const deps = [];
    const resolved = await Promise.all(parsed.intents.map(async (i) => [i, await resolveIntent(i).catch(() => undefined)]));
    for (const [i, version] of resolved) {
        if (!version)
            continue;
        deps.push({ ecosystem: i.ecosystem, name: i.name, version, direct: true, dev: false, source: i.kind === 'exact' ? 'command' : `command (${i.spec} resolves to ${version})`, tool: MANAGER_TOOL[i.manager] ?? 'npm' });
    }
    for (const f of parsed.requirementFiles) {
        const path = isAbsolute(f) ? f : resolve(cwd, f);
        try {
            deps.push(...parseRequirements(readFileSync(path, 'utf8'), f).deps);
        }
        catch {
            // missing file: pip will complain itself
        }
    }
    if (!deps.length)
        return;
    const findings = filterFindings(await checkDeps(deps, NET), min, true);
    if (!findings.length)
        return;
    const user = findings
        .map((f) => {
        const top = f.advisories[0];
        const more = f.advisories.length > 1 ? ` and ${f.advisories.length - 1} more` : '';
        const fix = f.safeVersion ? ` Safe version: ${f.safeVersion}.` : f.noFix ? ' No fixed version exists.' : '';
        return `${f.dep.name}@${f.dep.version} has known vulnerabilities [${f.severity}]: ${advisoryTitle(top)}${more}.${fix}`;
    })
        .join(' ');
    const fixes = findings.filter((f) => f.safeVersion).map((f) => `\`${fixCommand({ ...f.dep, source: 'requirements file' }, f.safeVersion)}\``);
    const claude = `pkgguard (OSV.dev) found known vulnerabilities in what this command installs:\n${formatBrief(findings, 10)}\n` +
        (fixes.length ? `Install a safe version instead, e.g. ${fixes.join(', ')}, ` : 'Prefer a different package or version, ') +
        'unless the user has explicitly asked for this exact version — in that case tell them about the vulnerability. ' +
        'The pkgguard MCP tools (check_package, get_vulnerability) give details.';
    const hookSpecificOutput = { hookEventName: 'PreToolUse', additionalContext: claude };
    if (mode !== 'warn') {
        hookSpecificOutput.permissionDecision = mode;
        hookSpecificOutput.permissionDecisionReason = mode === 'deny' ? claude : `pkgguard: ${user}`;
    }
    out({ hookSpecificOutput });
}
const DEP_COMMAND = /\b(npm|pnpm|yarn|bun)\s+(install|i|ci|add|update|up|upgrade)\b|\bpip3?\s+install\b|\bpython3?\s+-m\s+pip\s+install\b|\buv\s+(add|sync|lock|pip\s+install)\b|\bpoetry\s+(add|update|lock|install)\b|\bpipenv\s+(install|update|lock)\b|\bcargo\s+(add|update)\b|\bgo\s+(get|mod\s+tidy)\b|\bbundle\s+(add|update|install)\b|\bcomposer\s+(require|update|install)\b|\bdotnet\s+(add|restore)\b/;
async function postToolUse(input) {
    const root = projectRoot(input);
    const { min } = env();
    let findings = [];
    let what = '';
    if (input.tool_name === 'Bash') {
        // A dependency-changing command ran: re-scan lockfiles and report anything new.
        if (!DEP_COMMAND.test(String(input.tool_input?.command ?? '')))
            return;
        const r = await scanProject(root, { ...NET, minSeverity: min });
        const seen = seenGet(root);
        findings = r.findings.filter((f) => !seen.has(keyOf(f)));
        what = 'After that command, the project now contains';
    }
    else if (['Edit', 'Write', 'MultiEdit'].includes(String(input.tool_name))) {
        const file = String(input.tool_input?.file_path ?? '');
        const name = basename(file);
        if (!file || !isDependencyFile(name))
            return;
        let deps;
        if (name === 'package.json')
            deps = parsePackageJsonOnly(readFileSync(file, 'utf8'), name).deps;
        else
            deps = parseFile(file, root)?.deps ?? [];
        // Only packages the edit touched.
        const ti = input.tool_input ?? {};
        const changed = input.tool_name === 'Edit' ? ti.new_string : input.tool_name === 'MultiEdit' ? (ti.edits ?? []).map((e) => e?.new_string ?? '').join('\n') : undefined;
        // Match the full name, its last segment (Maven artifactId, Go/Packagist path tail) or the
        // version itself (an edit to a ${property} or a bare version line).
        if (changed !== undefined)
            deps = deps.filter((d) => [d.name, d.name.split(/[:/]/).pop(), d.version].some((s) => s && changed.includes(s)));
        if (!deps.length)
            return;
        findings = filterFindings(await checkDeps(deps, NET), min, true);
        what = `${name} now pins`;
    }
    else
        return;
    if (!findings.length)
        return;
    seenAdd(root, findings);
    out({
        hookSpecificOutput: {
            hookEventName: 'PostToolUse',
            additionalContext: `pkgguard (OSV.dev): ${what} vulnerable package versions (${countBySeverity(findings)}):\n${formatBrief(findings, 8)}\n` +
                'Tell the user, and move to the safe versions unless they want otherwise (pkgguard suggest_fixes gives exact commands).',
        },
    });
}
async function sessionStart(input) {
    const root = projectRoot(input);
    const { sessionMin } = env();
    const r = await scanProject(root, { ...NET, minSeverity: 'low' });
    seenAdd(root, r.findings);
    const important = filterFindings(r.findings, sessionMin, true);
    if (!important.length)
        return;
    out({
        hookSpecificOutput: {
            hookEventName: 'SessionStart',
            additionalContext: `pkgguard (OSV.dev): this project depends on ${important.length} package version(s) with known ${sessionMin}+ vulnerabilities (${countBySeverity(important)}):\n` +
                `${formatBrief(important, 8)}\n` +
                'Never add or keep these versions in new code. When dependencies come up, mention them; the pkgguard MCP tools scan_project and suggest_fixes give the full list and fix commands.',
        },
    });
}
async function readStdin() {
    const chunks = [];
    for await (const c of process.stdin)
        chunks.push(c);
    return Buffer.concat(chunks).toString('utf8');
}
export async function runHook() {
    if (process.env.PKGGUARD_DISABLE === '1')
        return;
    let input;
    try {
        input = JSON.parse(await readStdin());
    }
    catch {
        return;
    }
    const event = input.hook_event_name;
    const budget = Number(process.env.PKGGUARD_HOOK_BUDGET_MS) || (event === 'PreToolUse' ? 8000 : 20000);
    const work = (async () => {
        if (event === 'PreToolUse')
            await preToolUse(input);
        else if (event === 'PostToolUse')
            await postToolUse(input);
        else if (event === 'SessionStart')
            await sessionStart(input);
    })();
    const timeout = new Promise((r) => setTimeout(r, budget).unref());
    try {
        await Promise.race([work, timeout]);
    }
    catch (err) {
        process.stderr.write(`pkgguard hook: ${err.message}\n`);
    }
    if (result)
        await new Promise((r) => process.stdout.write(result, () => r()));
}
