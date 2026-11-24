import { createInterface } from 'node:readline';
import { isAbsolute, resolve } from 'node:path';
import { checkPackage, getVulnerability, parseEcosystem } from './check.js';
import { fixCommand } from './core/fix.js';
import { existingDir, pathVariants, projectDir } from './core/paths.js';
import { parseSeverity } from './core/severity.js';
import { countByFile, countBySeverity, findingJson, formatScan } from './format.js';
import { scanProject } from './scan.js';
import { VERSION } from './version.js';
/**
 * pkgguard MCP server — stdio, newline-delimited JSON-RPC 2.0, no SDK dependency.
 * Every tool is read-only: it reads lockfiles and asks OSV.dev, nothing else.
 */
const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const INSTRUCTIONS = `pkgguard checks dependencies against OSV.dev (GitHub Advisory DB, PyPA, RustSec, Go vulndb and more).
Use check_package before adding or upgrading a dependency and never choose a version it reports as vulnerable.
Use scan_project when the user asks about security, audits, outdated or vulnerable dependencies, and suggest_fixes for upgrade commands.
Prefer the smallest safe upgrade (same major version) and tell the user which CVEs a change resolves.`;
const SEVERITIES = ['low', 'moderate', 'high', 'critical'];
const TOOLS = [
    {
        name: 'scan_project',
        title: 'Scan project dependencies',
        description: 'Scan the project\'s lockfiles and manifests (npm/pnpm/yarn, pip/poetry/uv/pipenv, Go, Cargo, Bundler, Composer, NuGet, Maven/Gradle) and list every dependency version with known vulnerabilities, with severity, CVE IDs, how it is pulled in, and the lowest safe version.',
        inputSchema: {
            type: 'object',
            properties: {
                path: { type: 'string', description: 'Project directory (default: the current project).' },
                include_dev: { type: 'boolean', description: 'Include dev/test-only dependencies (default true).' },
                min_severity: { type: 'string', enum: SEVERITIES, description: 'Hide advisories below this severity (default low).' },
                limit: { type: 'number', description: 'Max packages to list in detail (default 40).' },
            },
        },
    },
    {
        name: 'check_package',
        title: 'Check a package version',
        description: 'Check whether a specific package version has known vulnerabilities. Without a version, lists every advisory on record for the package with the affected version ranges, and whether the latest release is clean. Use before adding or pinning a dependency.',
        inputSchema: {
            type: 'object',
            properties: {
                ecosystem: { type: 'string', description: 'npm, PyPI, Go, crates.io, Maven, RubyGems, Packagist or NuGet (aliases like pip, cargo, gem, composer accepted).' },
                name: { type: 'string', description: 'Package name. Maven: group:artifact. Go: module path. Packagist: vendor/package.' },
                version: { type: 'string', description: 'Exact version to check (optional).' },
            },
            required: ['ecosystem', 'name'],
        },
    },
    {
        name: 'get_vulnerability',
        title: 'Advisory details',
        description: 'Full details of an advisory by OSV, GHSA, CVE, PYSEC, RUSTSEC or GO id: summary, severity, affected packages and ranges, references.',
        inputSchema: {
            type: 'object',
            properties: { id: { type: 'string', description: 'e.g. GHSA-p6mc-m468-83gw or CVE-2020-8203' } },
            required: ['id'],
        },
    },
    {
        name: 'suggest_fixes',
        title: 'Suggest dependency fixes',
        description: 'Scan the project and return an upgrade plan: for each vulnerable dependency the safe version and the exact command or manifest edit to apply it (overrides/resolutions for transitive npm packages, cargo update --precise, go get, etc.).',
        inputSchema: {
            type: 'object',
            properties: {
                path: { type: 'string', description: 'Project directory (default: the current project).' },
                include_dev: { type: 'boolean', description: 'Include dev/test-only dependencies (default true).' },
                min_severity: { type: 'string', enum: SEVERITIES, description: 'Only fix advisories at or above this severity (default low).' },
            },
        },
    },
].map((t) => ({ ...t, annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true } }));
function projectPath(p) {
    const base = projectDir(process.env.CLAUDE_PROJECT_DIR, process.cwd());
    if (typeof p !== 'string' || !p.trim())
        return base;
    const tries = pathVariants(p).map((v) => (isAbsolute(v) ? v : resolve(base, v)));
    const full = tries.map(existingDir).find(Boolean);
    if (!full)
        throw new UserError(`Not a directory: ${tries[tries.length - 1]}`);
    return full;
}
class UserError extends Error {
}
function suggestText(findings) {
    if (!findings.length)
        return 'pkgguard: nothing to fix — no known vulnerabilities found.';
    const lines = [`pkgguard upgrade plan for ${findings.length} vulnerable package(s):`, ''];
    const unfixable = [];
    for (const f of findings) {
        const d = f.dep;
        if (!f.safeVersion) {
            unfixable.push(f);
            continue;
        }
        const all = [...new Set(f.advisories.map((a) => a.aliases.find((x) => x.startsWith('CVE-')) ?? a.id))];
        const ids = all.slice(0, 4).join(', ') + (all.length > 4 ? ` +${all.length - 4} more` : '');
        lines.push(`• ${d.name} ${d.version} → ${f.safeVersion}  [${f.severity}; ${ids}]  (${d.source})`);
        lines.push(`    ${fixCommand(d, f.safeVersion)}`);
        if (!d.direct && d.via?.length)
            lines.push(`    or upgrade ${d.via[0]} (the direct dependency that pulls it in) to a release that requires ${d.name} >= ${f.safeVersion}`);
    }
    if (unfixable.length) {
        lines.push('', 'No safe version available:');
        for (const f of unfixable) {
            lines.push(`• ${f.dep.name} ${f.dep.version} [${f.severity}] — ${f.noFix ? 'no fixed release exists; consider replacing it' : 'could not verify a safe version; see the advisory'} (${f.advisories.map((a) => a.id).join(', ')})`);
        }
    }
    lines.push('', 'After applying: run the project\'s tests, then scan_project again to confirm.');
    return lines.join('\n');
}
/**
 * Claude Code rejects tool results over ~25k tokens, and it counts the text and the
 * structuredContent together. Keep each well under that: ~20k characters.
 */
const BUDGET = Number(process.env.PKGGUARD_MCP_MAX_CHARS) || 20_000;
/** Build with `n` findings, halving `n` until both the text and the JSON fit the budget. */
function shrinkToFit(n, build) {
    let r = build(n);
    while (n > 1 && (r.text.length > BUDGET || JSON.stringify(r.json ?? null).length > BUDGET)) {
        n = Math.max(1, Math.floor(n / 2));
        r = build(n);
    }
    return r;
}
function fitScan(r, limit) {
    return shrinkToFit(Math.min(limit, r.findings.length), (n) => ({
        text: formatScan(r, n),
        json: {
            root: r.root,
            dependencies: r.dependencies,
            vulnerable: r.findings.length,
            bySeverity: countBySeverity(r.findings),
            byFile: countByFile(r.findings),
            shown: n,
            findings: r.findings.slice(0, n).map((f) => findingJson(f)),
            notes: r.notes,
        },
    }));
}
async function callTool(name, args) {
    switch (name) {
        case 'scan_project': {
            const r = await scanProject(projectPath(args.path), {
                includeDev: args.include_dev !== false,
                minSeverity: parseSeverity(args.min_severity, 'low'),
            });
            return fitScan(r, Number(args.limit) || 40);
        }
        case 'check_package': {
            const eco = parseEcosystem(String(args.ecosystem ?? ''));
            if (!eco)
                throw new UserError(`Unknown ecosystem "${args.ecosystem}". Use npm, PyPI, Go, crates.io, Maven, RubyGems, Packagist or NuGet.`);
            if (!args.name)
                throw new UserError('name is required');
            const version = typeof args.version === 'string' && args.version.trim() ? args.version.trim().replace(/^[=v](?=\d)/, '') : undefined;
            return checkPackage(eco, String(args.name).trim(), version);
        }
        case 'get_vulnerability': {
            const r = await getVulnerability(String(args.id ?? ''));
            if (!r)
                throw new UserError(`No OSV record for "${args.id}". OSV indexes GHSA/PYSEC/RUSTSEC/GO ids and many CVEs; try an alias listed by scan_project.`);
            return { text: r.text };
        }
        case 'suggest_fixes': {
            const r = await scanProject(projectPath(args.path), {
                includeDev: args.include_dev !== false,
                minSeverity: parseSeverity(args.min_severity, 'low'),
            });
            const notes = r.notes.length ? `\n\n${r.notes.map((n) => `Note: ${n}`).join('\n')}` : '';
            return shrinkToFit(r.findings.length, (n) => {
                const shown = r.findings.slice(0, n);
                const rest = r.findings.length - n;
                const more = rest ? `\n\n…and ${rest} more vulnerable packages, less severe than the ones above. Fix these first, or pass "min_severity" or a "path" to one project to see the rest.` : '';
                return {
                    text: suggestText(shown) + more + notes,
                    json: { total: r.findings.length, shown: n, fixes: shown.map((f) => findingJson(f, 1)) },
                };
            });
        }
    }
    throw new UserError(`Unknown tool: ${name}`);
}
function send(msg) {
    process.stdout.write(JSON.stringify(msg) + '\n');
}
async function handle(msg) {
    const { id, method, params } = msg ?? {};
    const isRequest = id !== undefined && id !== null;
    const reply = (result) => {
        if (isRequest)
            send({ jsonrpc: '2.0', id, result });
    };
    const fail = (code, message) => {
        if (isRequest)
            send({ jsonrpc: '2.0', id, error: { code, message } });
    };
    switch (method) {
        case 'initialize': {
            const asked = params?.protocolVersion;
            return reply({
                protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[1],
                capabilities: { tools: { listChanged: false } },
                serverInfo: { name: 'pkgguard', title: 'pkgguard — dependency vulnerabilities', version: VERSION },
                instructions: INSTRUCTIONS,
            });
        }
        case 'ping':
            return reply({});
        case 'tools/list':
            return reply({ tools: TOOLS });
        case 'tools/call': {
            const name = params?.name;
            try {
                const r = await callTool(name, params?.arguments ?? {});
                return reply({
                    content: [{ type: 'text', text: r.text }],
                    ...(r.json && typeof r.json === 'object' && !Array.isArray(r.json) ? { structuredContent: r.json } : {}),
                });
            }
            catch (err) {
                const message = err instanceof UserError ? err.message : `pkgguard could not complete ${name}: ${err?.message ?? err} (OSV.dev may be unreachable).`;
                return reply({ content: [{ type: 'text', text: message }], isError: true });
            }
        }
        case 'resources/list':
            return reply({ resources: [] });
        case 'prompts/list':
            return reply({ prompts: [] });
        default:
            if (typeof method === 'string' && method.startsWith('notifications/'))
                return;
            return fail(-32601, `Method not found: ${method}`);
    }
}
export function runMcpServer() {
    const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
    rl.on('line', (line) => {
        if (!line.trim())
            return;
        let msg;
        try {
            msg = JSON.parse(line);
        }
        catch {
            send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
            return;
        }
        for (const m of Array.isArray(msg) ? msg : [msg]) {
            handle(m).catch((err) => process.stderr.write(`pkgguard mcp: ${err?.stack ?? err}\n`));
        }
    });
    rl.on('close', () => process.exit(0));
}
