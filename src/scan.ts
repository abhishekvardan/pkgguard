import type { Advisory, Dep, Finding, ScanResult, Severity } from './types.js';
import { resolveSafeVersions } from './core/fix.js';
import { advisoriesFor, normalizeName, type NetOpts } from './core/osv.js';
import { atLeast, maxSeverity } from './core/severity.js';
import { SEVERITY_RANK } from './types.js';
import { parseProject } from './parsers/detect.js';

export interface ScanOpts extends NetOpts {
  includeDev?: boolean;
  minSeverity?: Severity;
  /** Skip the extra OSV round-trips that verify suggested safe versions. */
  skipSafeVersions?: boolean;
}

/** Merge duplicates (same package+version from several lockfiles / workspaces). */
export function dedupe(deps: Dep[]): Dep[] {
  const map = new Map<string, Dep>();
  for (const d of deps) {
    const k = `${d.ecosystem}|${normalizeName(d.ecosystem, d.name)}|${d.version}`;
    const prev = map.get(k);
    if (!prev) {
      map.set(k, { ...d });
      continue;
    }
    if (d.direct && !prev.direct) {
      prev.direct = true;
      delete prev.via;
      prev.source = d.source;
      prev.tool = d.tool;
    }
    prev.dev = prev.dev && d.dev;
  }
  return [...map.values()];
}

/** Check a list of dependencies against OSV and build findings (no filtering). */
export async function checkDeps(deps: Dep[], opts: ScanOpts = {}): Promise<Finding[]> {
  if (!deps.length) return [];
  const results = await advisoriesFor(
    deps.map((d) => ({ ecosystem: d.ecosystem, name: d.name, version: d.version })),
    opts,
  );
  const findings: Finding[] = [];
  deps.forEach((dep, i) => {
    const advisories: Advisory[] = [...(results[i] ?? [])].sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.score ?? 0) - (a.score ?? 0) || (b.published ?? '').localeCompare(a.published ?? ''),
    );
    if (!advisories.length) return;
    findings.push({ dep, advisories, severity: maxSeverity(advisories.map((a) => a.severity)), noFix: false });
  });
  if (!opts.skipSafeVersions) await resolveSafeVersions(findings, opts);
  return sortFindings(findings);
}

export function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      Number(b.dep.direct) - Number(a.dep.direct) ||
      Number(a.dep.dev) - Number(b.dep.dev) ||
      a.dep.name.localeCompare(b.dep.name),
  );
}

export function filterFindings(findings: Finding[], min: Severity, includeDev: boolean): Finding[] {
  return findings
    .filter((f) => includeDev || !f.dep.dev)
    .map((f) => {
      const advisories = f.advisories.filter((a) => atLeast(a.severity, min));
      return { ...f, advisories, severity: maxSeverity(advisories.map((a) => a.severity)) };
    })
    .filter((f) => f.advisories.length);
}

export async function scanProject(root: string, opts: ScanOpts = {}): Promise<ScanResult> {
  const { manifests, errors } = parseProject(root);
  const notes = [...errors];
  const unpinned = manifests.reduce((n, m) => n + m.unpinned, 0);
  if (unpinned) notes.push(`${unpinned} dependencies have version ranges instead of exact versions (no lockfile), so they were not checked.`);
  if (!manifests.length) notes.push('No lockfiles or manifests found.');
  let deps = dedupe(manifests.flatMap((m) => m.deps));
  if (opts.includeDev === false) deps = deps.filter((d) => !d.dev);
  const all = await checkDeps(deps, opts);
  const findings = filterFindings(all, opts.minSeverity ?? 'low', opts.includeDev !== false);
  const hidden = all.length - findings.length;
  if (hidden > 0) notes.push(`${hidden} vulnerable package(s) below the "${opts.minSeverity}" threshold were hidden.`);
  return {
    root,
    manifests: manifests.map((m) => ({ path: m.path, ecosystem: m.ecosystem, tool: m.tool, deps: m.deps.length })),
    dependencies: deps.length,
    findings,
    notes,
  };
}
