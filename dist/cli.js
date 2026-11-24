#!/usr/bin/env node
import { resolve } from 'node:path';
import { checkPackage, getVulnerability, parseEcosystem } from './check.js';
import { parseSeverity } from './core/severity.js';
import { findingJson, formatScan } from './format.js';
import { runHook } from './hook.js';
import { runMcpServer } from './mcp.js';
import { scanProject } from './scan.js';
import { VERSION } from './version.js';
const HELP = `pkgguard ${VERSION} — known vulnerabilities in your dependencies (OSV.dev)

Usage:
  pkgguard scan [path] [--min low|moderate|high|critical] [--no-dev] [--json]
      Scan lockfiles under path (default: .). Exits 1 when something is found.
  pkgguard check <ecosystem> <name> [version] [--json]
      e.g. pkgguard check npm lodash 4.17.15 · pkgguard check pypi requests
  pkgguard vuln <id>
      Advisory details, e.g. pkgguard vuln CVE-2021-44906
  pkgguard mcp      Run the MCP server on stdio (used by the Claude Code plugin)
  pkgguard hook     Run as a Claude Code hook (reads the event JSON on stdin)

Environment:
  PKGGUARD_MIN_SEVERITY          hook threshold for install/edit warnings (default moderate)
  PKGGUARD_SESSION_MIN_SEVERITY  threshold for the session-start summary (default high)
  PKGGUARD_HOOK_MODE             ask (default) | deny | warn — what to do before a vulnerable install
  PKGGUARD_DISABLE=1             turn the hooks off
  PKGGUARD_CACHE_DIR             cache location (default ~/.cache/pkgguard)`;
function flag(args, name) {
    const i = args.findIndex((a) => a === name || a.startsWith(`${name}=`));
    if (i < 0)
        return undefined;
    const a = args[i];
    args.splice(i, 1);
    if (a.includes('='))
        return a.split('=')[1];
    const next = args[i];
    if (next !== undefined && !next.startsWith('-')) {
        args.splice(i, 1);
        return next;
    }
    return true;
}
async function main(argv) {
    const args = [...argv];
    const cmd = args.shift();
    switch (cmd) {
        case 'mcp':
            runMcpServer();
            return -1; // keep running
        case 'hook':
            await runHook();
            return 0;
        case 'scan': {
            const json = flag(args, '--json') !== undefined;
            const min = flag(args, '--min');
            const noDev = flag(args, '--no-dev') !== undefined;
            const r = await scanProject(resolve(args[0] ?? '.'), {
                minSeverity: parseSeverity(typeof min === 'string' ? min : undefined, 'low'),
                includeDev: !noDev,
            });
            if (json)
                console.log(JSON.stringify({ ...r, findings: r.findings.map(findingJson) }, null, 2));
            else
                console.log(formatScan(r, 1000));
            return r.findings.length ? 1 : 0;
        }
        case 'check': {
            const json = flag(args, '--json') !== undefined;
            const [ecoArg, name, version] = args;
            const eco = ecoArg ? parseEcosystem(ecoArg) : undefined;
            if (!eco || !name) {
                console.error('Usage: pkgguard check <ecosystem> <name> [version]');
                return 2;
            }
            const r = await checkPackage(eco, name, version);
            console.log(json ? JSON.stringify(r.json, null, 2) : r.text);
            return r.json?.vulnerable || r.json?.latestVulnerable ? 1 : 0;
        }
        case 'vuln': {
            if (!args[0]) {
                console.error('Usage: pkgguard vuln <id>');
                return 2;
            }
            const r = await getVulnerability(args[0]);
            if (!r) {
                console.error(`No OSV record for ${args[0]}`);
                return 2;
            }
            console.log(r.text);
            return 0;
        }
        case '-v':
        case '--version':
        case 'version':
            console.log(VERSION);
            return 0;
        case undefined:
        case '-h':
        case '--help':
        case 'help':
            console.log(HELP);
            return 0;
        default:
            console.error(`Unknown command: ${cmd}\n\n${HELP}`);
            return 2;
    }
}
main(process.argv.slice(2)).then((code) => {
    if (code >= 0)
        process.exit(code);
}, (err) => {
    console.error(`pkgguard: ${err?.message ?? err}`);
    // A hook must never fail loudly.
    process.exit(process.argv[2] === 'hook' ? 0 : 2);
});
