import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Dep, Finding, Severity } from '../types.js';
import { isExactVersion } from '../core/version.js';
import { atLeast, parseSeverity } from '../core/severity.js';
import { diffFindings, fingerprints } from '../diff.js';
import { advisoryTitle, countBySeverity, formatBrief } from '../format.js';
import { parseInstallCommand, type InstallIntent } from '../installSpec.js';
import { applyPolicy, loadPolicy } from '../policy.js';
import { intentDep, resolveIntent } from '../resolve.js';
import { checkDeps, filterFindings, scanProject } from '../scan.js';
import { detectManager, MANAGER_ECOSYSTEM, MANAGER_FILES, type Manager } from './detect.js';
import { addCommands, runCmd, showCmd, syncCommand, type AddItem } from './run.js';

/**
 * `pkgguard add <pkg…>`: a guarded front for the project's own package manager.
 *  1. resolve what each spec would install and check it against OSV.dev;
 *  2. swap a vulnerable version for the nearest safe one (or refuse when none exists);
 *  3. run the real install;
 *  4. re-scan and report vulnerable packages the install pulled in transitively
 *     (`--strict`: put the manifest and lockfile back and fail).
 */

export function parseSpec(m: Manager, spec: string): InstallIntent | undefined {
  const eco = MANAGER_ECOSYSTEM[m];
  if (eco === 'npm') {
    const i = parseInstallCommand(`npm install "${spec.replace(/"/g, '')}"`).intents[0];
    return i && { ...i, manager: m };
  }
  if (eco === 'PyPI') {
    const i = parseInstallCommand(`pip install "${spec.replace(/"/g, '')}"`).intents[0];
    return i && { ...i, manager: m };
  }
  // Everything else: name@version (composer also name:version).
  let name = spec;
  let ver = '';
  const at = spec.lastIndexOf('@');
  const colon = m === 'composer' ? spec.lastIndexOf(':') : -1;
  const cut = Math.max(at, colon);
  if (cut > 0) {
    name = spec.slice(0, cut);
    ver = spec.slice(cut + 1).trim();
  }
  if (!name || /^[.~/\\]|^[A-Za-z]:[\\/]|:\/\//.test(name)) return undefined; // local path or URL
  const bare = ver.replace(/^[=v]+/, '');
  if (!ver || ver === 'latest') return { ecosystem: eco, name, kind: 'latest', spec, manager: m };
  if (isExactVersion(bare)) return { ecosystem: eco, name, kind: 'exact', version: bare, spec, manager: m };
  return { ecosystem: eco, name, kind: 'range', version: ver, spec, manager: m };
}

export interface AddOpts {
  cwd: string;
  pm?: string;
  dev?: boolean;
  strict?: boolean;
  allowVulnerable?: boolean;
  dryRun?: boolean;
  min?: Severity;
  /** Extra arguments passed to the package manager as-is (after `--`). */
  extra?: string[];
  log?: (s: string) => void;
}

interface Planned {
  item: AddItem;
  intent?: InstallIntent;
  resolved?: string;
  finding?: Finding;
}

/** Decide what to install: pure given the findings, so it can be tested offline. */
export function planItems(
  specs: { original: string; intent?: InstallIntent; resolved?: string }[],
  findings: Finding[],
  allowVulnerable = false,
): { planned: Planned[]; blocked: Planned[]; notes: string[] } {
  const notes: string[] = [];
  const planned: Planned[] = [];
  const blocked: Planned[] = [];
  for (const s of specs) {
    const i = s.intent;
    const item: AddItem = { name: i?.name ?? s.original, version: i?.kind === 'latest' ? undefined : i?.version, original: s.original, changed: false };
    const p: Planned = { item, intent: i, resolved: s.resolved };
    if (!i) notes.push(`${s.original}: not a registry package (path, URL or git) — installed without checking.`);
    else if (!s.resolved) notes.push(`${s.original}: could not tell which version this installs (offline, or a range pkgguard can't resolve for this ecosystem) — installed without checking.`);
    const f = i && s.resolved ? findings.find((x) => x.dep.name === i.name && x.dep.version === s.resolved) : undefined;
    if (f) {
      p.finding = f;
      const top = f.advisories[0]!;
      const what = `${i!.name}@${s.resolved} has ${f.advisories.length} known vulnerabilit${f.advisories.length === 1 ? 'y' : 'ies'} [${f.severity}], e.g. ${advisoryTitle(top)} ${top.summary}`;
      if (f.safeVersion && !allowVulnerable) {
        item.version = f.safeVersion;
        item.changed = true;
        const outside = i!.kind === 'range' ? ` (outside the range "${i!.version}" you asked for)` : i!.kind === 'latest' ? ' (newer than the latest stable release — a pre-release or patched build)' : '';
        notes.push(`${what}\n  → installing ${i!.name}@${f.safeVersion} instead${outside}.`);
      } else if (allowVulnerable) {
        notes.push(`${what}\n  → installing it anyway (--allow-vulnerable).`);
      } else {
        notes.push(`${what}\n  → no fixed version exists${f.noFix ? '' : ' that pkgguard could verify'}. Refusing to install it; pick another package, or pass --allow-vulnerable to accept the risk.`);
        blocked.push(p);
        continue;
      }
    }
    planned.push(p);
  }
  return { planned, blocked, notes };
}

function backup(root: string, m: Manager): Map<string, string | undefined> {
  const files = new Map<string, string | undefined>();
  for (const f of MANAGER_FILES[m]) {
    const p = join(root, f);
    files.set(p, existsSync(p) ? readFileSync(p, 'utf8') : undefined);
  }
  return files;
}

function restore(files: Map<string, string | undefined>): void {
  for (const [p, text] of files) {
    if (text === undefined) {
      if (existsSync(p)) unlinkSync(p);
    } else writeFileSync(p, text);
  }
}

export async function runAdd(specs: string[], opts: AddOpts): Promise<number> {
  const log = opts.log ?? ((s: string) => console.error(s));
  if (!specs.length) {
    log('Usage: pkgguard add <package[@version]>… [-D] [--strict] [--pm npm|pnpm|…] [--dry-run] [-- <args for the package manager>]');
    return 2;
  }
  const det = detectManager(opts.cwd, opts.pm);
  if (!det) {
    log('pkgguard: no project here (no package.json, pyproject.toml, Cargo.toml, go.mod, Gemfile, composer.json or *.csproj found). Pass --pm to choose a package manager.');
    return 2;
  }
  const { manager, root } = det;
  const { policy, warnings } = loadPolicy(root);
  warnings.forEach((w) => log(`pkgguard: ${w}`));
  const min = opts.min ?? parseSeverity(process.env.PKGGUARD_MIN_SEVERITY, policy.minSeverity ?? 'moderate');

  // 1. resolve and check
  const parsed = specs.map((original) => ({ original, intent: parseSpec(manager, original) }));
  const resolved = await Promise.all(parsed.map(async (p) => ({ ...p, resolved: p.intent ? await resolveIntent(p.intent).catch(() => undefined) : undefined })));
  const deps: Dep[] = resolved.filter((r) => r.intent && r.resolved).map((r) => intentDep(r.intent!, r.resolved!, opts.dev));
  let findings: Finding[] = [];
  if (deps.length) {
    try {
      findings = applyPolicy(filterFindings(await checkDeps(deps), min, true), policy).findings;
    } catch (err) {
      log(`pkgguard: could not reach OSV.dev (${(err as Error).message}); installing without checking.`);
    }
  }

  // 2. plan
  const { planned, blocked, notes } = planItems(resolved, findings, opts.allowVulnerable);
  notes.forEach((n) => log(`pkgguard: ${n}`));
  if (blocked.length) {
    log(`pkgguard: nothing was installed.`);
    return 2;
  }
  const clean = resolved.filter((r) => r.resolved && !findings.some((f) => f.dep.name === r.intent?.name)).map((r) => `${r.intent!.name}@${r.resolved}`);
  if (clean.length) log(`pkgguard: ${clean.join(', ')}: no known vulnerabilities.`);
  const cmds = addCommands(manager, planned.map((p) => p.item), !!opts.dev, opts.extra);
  log(`pkgguard: ${cmds.map(showCmd).join(' && ')}`);
  if (opts.dryRun) return 0;

  // 3. install (with a baseline for what it pulls in)
  const before = await scanProject(root, { minSeverity: min, skipSafeVersions: true }).catch(() => undefined);
  const saved = opts.strict ? backup(root, manager) : undefined;
  for (const c of cmds) {
    const code = runCmd(c, root);
    if (code !== 0) {
      if (saved) {
        restore(saved);
        log('pkgguard: the install failed; manifest and lockfile restored.');
      }
      return code;
    }
  }
  if (!before) return 0;

  // 4. what came in with it
  const after = await scanProject(root, { minSeverity: min }).catch(() => undefined);
  if (!after) return 0;
  const introduced = diffFindings(fingerprints(before.findings), after.findings).added;
  if (!introduced.length) {
    log('pkgguard: ✓ the install added no known vulnerabilities.');
    return 0;
  }
  log(`pkgguard: the install brought in vulnerable versions (${countBySeverity(introduced)}):\n${formatBrief(introduced, 10)}`);
  if (saved && introduced.some((f) => atLeast(f.severity, min))) {
    restore(saved);
    const sync = syncCommand(manager, root);
    if (sync) runCmd(sync, root);
    log('pkgguard: --strict: manifest and lockfile restored to how they were. Upgrade the package that pulls these in, or ask Claude to /pkgguard:fix.');
    return 2;
  }
  log('pkgguard: they were installed. To fix them run `pkgguard scan` for the commands, or ask Claude to /pkgguard:fix.');
  return 0;
}
