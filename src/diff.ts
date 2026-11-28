import { readFileSync } from 'node:fs';
import type { Finding } from './types.js';
import { maxSeverity } from './core/severity.js';
import { normalizeName } from './core/osv.js';

/**
 * A fingerprint names one advisory on one package version: `npm:lodash@4.17.15#GHSA-p6mc-m468-83gw`.
 * Comparing fingerprint sets tells what is new since an earlier scan — a newly published CVE
 * against a version you already had, or a vulnerable version that an install brought in.
 */

export function fingerprint(f: Pick<Finding, 'dep'>, advisoryId: string): string {
  return `${f.dep.ecosystem}:${normalizeName(f.dep.ecosystem, f.dep.name)}@${f.dep.version}#${advisoryId}`;
}

export function fingerprints(findings: Finding[]): string[] {
  return [...new Set(findings.flatMap((f) => f.advisories.map((a) => fingerprint(f, a.id))))].sort();
}

export interface Diff {
  /** Findings narrowed to their advisories that were not in the baseline. */
  added: Finding[];
  /** Baseline fingerprints that are gone (upgraded, removed, or the advisory was withdrawn). */
  resolved: string[];
  unchanged: number;
}

export function diffFindings(baseline: Iterable<string>, findings: Finding[]): Diff {
  const before = new Set(baseline);
  const now = new Set<string>();
  const added: Finding[] = [];
  let unchanged = 0;
  for (const f of findings) {
    const fresh = f.advisories.filter((a) => {
      const fp = fingerprint(f, a.id);
      now.add(fp);
      if (before.has(fp)) {
        unchanged++;
        return false;
      }
      return true;
    });
    if (fresh.length) added.push({ ...f, advisories: fresh, severity: maxSeverity(fresh.map((a) => a.severity)) });
  }
  return { added, resolved: [...before].filter((fp) => !now.has(fp)).sort(), unchanged };
}

/** Read a baseline: the output of `pkgguard scan --json` (or any JSON with a `fingerprints` array). */
export function readBaseline(file: string): string[] {
  const j = JSON.parse(readFileSync(file, 'utf8'));
  if (Array.isArray(j?.fingerprints)) return j.fingerprints.map(String);
  if (Array.isArray(j?.findings)) {
    return j.findings.flatMap((f: any) =>
      (f.advisories ?? []).map((a: any) => fingerprint({ dep: { ecosystem: f.ecosystem, name: f.name, version: f.version } as Finding['dep'] }, a.id)),
    );
  }
  throw new Error(`${file} is not a pkgguard baseline (expected the output of \`pkgguard scan --json\`).`);
}

/** "npm lodash 4.17.15 (GHSA-…)" for a fingerprint. */
export function describeFingerprint(fp: string): string {
  const m = fp.match(/^([^:]+):(.+)@([^@#]+)#(.+)$/);
  return m ? `${m[1]} ${m[2]} ${m[3]} (${m[4]})` : fp;
}
