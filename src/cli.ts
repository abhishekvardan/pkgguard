#!/usr/bin/env node
import { resolve } from 'node:path';
import { checkPackage, getVulnerability, parseEcosystem } from './check.js';
import type { Severity } from './types.js';
import { atLeast, parseSeverity } from './core/severity.js';
import { projectDir } from './core/paths.js';
import { describeFingerprint, diffFindings, fingerprints, readBaseline } from './diff.js';
import { findingJson, formatScan } from './format.js';
import { loadPolicy } from './policy.js';
import { runAdd } from './pm/add.js';
import { runInstall } from './pm/install.js';
import { runWatch } from './watch/watch.js';
import { installSchedule, removeSchedule, runScheduleNow, scheduleStatus } from './watch/schedule.js';
import { runHook } from './hook.js';
import { runMcpServer } from './mcp.js';
import { scanProject } from './scan.js';
import { VERSION } from './version.js';

const HELP = `pkgguard ${VERSION} — known vulnerabilities in your dependencies (OSV.dev)

Usage:
  pkgguard scan [path] [--min <sev>] [--fail-on <sev>] [--no-dev] [--json] [--baseline <file>]
      Scan lockfiles under path (default: .). Exits 1 when something at or above
      --fail-on (default: the policy's failOn, else any) is found. --baseline <file>
      (the output of an earlier scan --json) reports and fails on NEW findings only.

Guarded installs (instead of npm/pnpm/yarn/bun, pip/uv/poetry/pipenv, cargo, go, bundle, composer, dotnet):
  pkgguard add <pkg[@version]>... [-D] [--strict] [--allow-vulnerable] [--dry-run] [--pm <manager>] [-- <args>]
      Checks each package first and installs a safe version instead of a vulnerable one
      (refuses when none exists), then reports vulnerable packages the install pulled in.
      --strict puts the package files back and fails if the install brought any in.
  pkgguard install [--ci] [--allow-vulnerable] [--fail-on <sev>] [--pm <manager>] [-- <args>]
      Installs from the lockfile, but refuses when it pins failOn+ (default high) vulnerabilities.

Always-on watcher:
  pkgguard watch <folder>... [--notify] [--min <sev>] [--json]
      Scans every project under the folders and reports what is NEW since the last run:
      newly published advisories against versions you already have. The next Claude
      session in that project hears about them too. Exits 1 when something new is found.
  pkgguard schedule install --every <30m|6h|1d> <folder>...   run the watch on a timer, with notifications
  pkgguard schedule status | run | remove
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
  PKGGUARD_FAIL_ON               severity that fails the install/scan gates (default: policy failOn)
  PKGGUARD_DISABLE=1             turn the hooks off
  PKGGUARD_STATE_DIR             watcher state and logs (default ~/.pkgguard)
  PKGGUARD_CACHE_DIR             cache location (default ~/.cache/pkgguard)`;

function flag(args: string[], name: string): string | true | undefined {
  const i = args.findIndex((a) => a === name || a.startsWith(`${name}=`));
  if (i < 0) return undefined;
  const a = args[i]!;
  args.splice(i, 1);
  if (a.includes('=')) return a.split('=')[1];
  const next = args[i];
  if (next !== undefined && !next.startsWith('-')) {
    args.splice(i, 1);
    return next;
  }
  return true;
}

/** Remove a boolean flag (any of its spellings) and say whether it was there. */
function bool(args: string[], ...names: string[]): boolean {
  let found = false;
  for (let i = args.length - 1; i >= 0; i--) {
    if (names.includes(args[i]!)) {
      args.splice(i, 1);
      found = true;
    }
  }
  return found;
}

/** A value flag: `--name value` or `--name=value`. */
function value(args: string[], name: string): string | undefined {
  const v = flag(args, name);
  return typeof v === 'string' ? v : undefined;
}

const sev = (s: string | undefined, fallback: Severity): Severity => parseSeverity(s, fallback);

function parseAddArgs(argsIn: string[]) {
  const args = [...argsIn];
  const opts = {
    cwd: process.cwd(),
    dev: bool(args, '-D', '--dev', '--save-dev', '-d'),
    strict: bool(args, '--strict'),
    allowVulnerable: bool(args, '--allow-vulnerable'),
    dryRun: bool(args, '--dry-run', '-n'),
    pm: value(args, '--pm'),
    min: undefined as Severity | undefined,
  };
  const min = value(args, '--min');
  if (min) opts.min = sev(min, 'moderate');
  const unknown = args.filter((a) => a.startsWith('-'));
  if (unknown.length) throw new Error(`Unknown option(s): ${unknown.join(' ')}. Pass package-manager options after "--".`);
  return { specs: args, opts };
}

async function main(argv: string[]): Promise<number> {
  const dd = argv.indexOf('--');
  const passthrough = dd >= 0 ? argv.slice(dd + 1) : [];
  const args = dd >= 0 ? argv.slice(0, dd) : [...argv];
  const cmd = args.shift();
  switch (cmd) {
    case 'mcp':
      runMcpServer();
      return -1; // keep running
    case 'hook':
      await runHook();
      return 0;
    case 'scan': {
      const json = bool(args, '--json');
      const noDev = bool(args, '--no-dev');
      const min = sev(value(args, '--min'), 'low');
      const failOnArg = value(args, '--fail-on');
      const baselineFile = value(args, '--baseline');
      const root = args[0] ? resolve(args[0]) : projectDir(process.cwd());
      const failOn = sev(failOnArg ?? process.env.PKGGUARD_FAIL_ON, loadPolicy(root).policy.failOn ?? 'low');
      const r = await scanProject(root, { minSeverity: min, includeDev: !noDev });
      let findings = r.findings;
      let resolvedSince: string[] = [];
      if (baselineFile) {
        const d = diffFindings(readBaseline(baselineFile), r.findings);
        findings = d.added;
        resolvedSince = d.resolved;
        r.notes.unshift(`Compared with ${baselineFile}: ${d.added.length} package(s) with new advisories, ${d.resolved.length} advisory hit(s) resolved, ${d.unchanged} unchanged.`);
      }
      if (json) {
        const extra = baselineFile ? { resolved: resolvedSince } : {};
        console.log(JSON.stringify({ ...r, findings: findings.map((f) => findingJson(f, Infinity)), fingerprints: fingerprints(r.findings), ...extra }, null, 2));
      } else {
        console.log(formatScan({ ...r, findings }, 1000));
        if (resolvedSince.length) console.log('Resolved since the baseline:\n' + resolvedSince.map((fp) => '  ' + describeFingerprint(fp)).join('\n'));
      }
      return findings.some((f) => atLeast(f.severity, failOn)) ? 1 : 0;
    }
    case 'add': {
      const { specs, opts } = parseAddArgs(args);
      return runAdd(specs, { ...opts, extra: passthrough });
    }
    case 'install': {
      if (args.some((a) => !a.startsWith('-'))) {
        // `pkgguard install lodash`, out of npm habit: that is an add.
        const { specs, opts } = parseAddArgs(args);
        return runAdd(specs, { ...opts, extra: passthrough });
      }
      const failOn = value(args, '--fail-on');
      return runInstall({
        cwd: process.cwd(),
        ci: bool(args, '--ci', '--frozen'),
        allowVulnerable: bool(args, '--allow-vulnerable'),
        pm: value(args, '--pm'),
        failOn: failOn ? sev(failOn, 'high') : undefined,
        extra: passthrough,
      });
    }
    case 'watch': {
      const notify = bool(args, '--notify');
      const json = bool(args, '--json');
      const min = value(args, '--min');
      if (!args.length) args.push('.');
      const { alert } = await runWatch(args, { notify, json, min: min ? sev(min, 'moderate') : undefined });
      return alert.length ? 1 : 0;
    }
    case 'schedule': {
      const sub = args.shift();
      if (sub === 'install') {
        const every = value(args, '--every') ?? '6h';
        const min = value(args, '--min');
        console.log(installSchedule(args, every, min ? ['--min', min] : []));
        return 0;
      }
      if (sub === 'status') {
        console.log(scheduleStatus());
        return 0;
      }
      if (sub === 'run') {
        console.log(runScheduleNow());
        return 0;
      }
      if (sub === 'remove' || sub === 'uninstall') {
        console.log(removeSchedule());
        return 0;
      }
      console.error('Usage: pkgguard schedule install --every 6h <folder>... | status | run | remove');
      return 2;
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

main(process.argv.slice(2)).then(
  (code) => {
    if (code >= 0) process.exit(code);
  },
  (err) => {
    console.error(`pkgguard: ${(err as Error)?.message ?? err}`);
    // A hook must never fail loudly.
    process.exit(process.argv[2] === 'hook' ? 0 : 2);
  },
);
