import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { Finding, Severity } from './types.js';
import { maxSeverity, parseSeverity } from './core/severity.js';

/**
 * Per-repo policy, read from `.pkgguard.json` in the project root or the nearest parent:
 *
 *   { "minSeverity": "moderate", "failOn": "high",
 *     "ignore": [{ "id": "GHSA-…", "reason": "not reachable", "until": "2027-01-31" }] }
 *
 * - minSeverity: threshold for the install/edit warnings (env PKGGUARD_MIN_SEVERITY wins).
 * - failOn: lowest severity that fails `pkgguard scan`, `install`, `watch` (and blocks `add --strict`).
 * - ignore: accepted risks. Matches the advisory id or any alias (CVE). Optional "package" narrows it
 *   to one package. An ignore past its "until" date stops applying, with a warning.
 */

export interface Ignore {
  id: string;
  package?: string;
  reason?: string;
  until?: string;
}

export interface Policy {
  minSeverity?: Severity;
  failOn?: Severity;
  ignore: Ignore[];
  /** Where it was read from. */
  file?: string;
}

export const POLICY_FILE = '.pkgguard.json';

const cache = new Map<string, { policy: Policy; warnings: string[] }>();

/** Find and read the nearest `.pkgguard.json` at or above `root`. Never throws. */
export function loadPolicy(root: string): { policy: Policy; warnings: string[] } {
  const key = resolve(root);
  const hit = cache.get(key);
  if (hit) return hit;
  let dir = key;
  let found: { policy: Policy; warnings: string[] } = { policy: { ignore: [] }, warnings: [] };
  for (let i = 0; i < 20; i++) {
    const file = join(dir, POLICY_FILE);
    if (existsSync(file)) {
      found = parsePolicy(readFileSync(file, 'utf8'), file);
      break;
    }
    if (existsSync(join(dir, '.git'))) break; // don't leak a policy across repositories
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  cache.set(key, found);
  return found;
}

export function parsePolicy(text: string, file = POLICY_FILE): { policy: Policy; warnings: string[] } {
  const warnings: string[] = [];
  let raw: any;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return { policy: { ignore: [], file }, warnings: [`${file} is not valid JSON (${(e as Error).message}); it was ignored.`] };
  }
  const sev = (v: unknown, field: string): Severity | undefined => {
    if (v === undefined) return undefined;
    const s = parseSeverity(String(v), 'unknown');
    if (s === 'unknown') {
      warnings.push(`${file}: "${field}" must be low, moderate, high or critical.`);
      return undefined;
    }
    return s;
  };
  const ignore: Ignore[] = [];
  for (const [i, e] of (Array.isArray(raw?.ignore) ? raw.ignore : []).entries()) {
    const entry = typeof e === 'string' ? { id: e } : e;
    if (!entry || typeof entry.id !== 'string' || !entry.id.trim()) {
      warnings.push(`${file}: ignore[${i}] needs an "id" (an advisory id such as GHSA-… or CVE-…).`);
      continue;
    }
    if (entry.until !== undefined && Number.isNaN(Date.parse(String(entry.until)))) warnings.push(`${file}: ignore[${i}] "until" is not a date (use YYYY-MM-DD).`);
    ignore.push({ id: entry.id.trim(), package: entry.package, reason: entry.reason, until: entry.until === undefined ? undefined : String(entry.until) });
  }
  return { policy: { minSeverity: sev(raw?.minSeverity, 'minSeverity'), failOn: sev(raw?.failOn, 'failOn'), ignore, file }, warnings };
}

function expired(i: Ignore, now: Date): boolean {
  if (!i.until) return false;
  const t = Date.parse(i.until);
  // "until 2027-01-31" includes that whole day.
  return !Number.isNaN(t) && now.getTime() > t + 24 * 60 * 60 * 1000 - 1;
}

/** Drop ignored advisories (and findings left with none). Expired ignores don't apply and are reported. */
export function applyPolicy(findings: Finding[], policy: Policy, now = new Date()): { findings: Finding[]; ignored: number; warnings: string[] } {
  if (!policy.ignore.length) return { findings, ignored: 0, warnings: [] };
  const warnings = new Set<string>();
  const active = policy.ignore.filter((i) => {
    if (!expired(i, now)) return true;
    warnings.add(`The ignore for ${i.id}${i.package ? ` (${i.package})` : ''} in ${policy.file ?? POLICY_FILE} expired on ${i.until}, so it is reported again.`);
    return false;
  });
  let ignored = 0;
  const out: Finding[] = [];
  for (const f of findings) {
    const advisories = f.advisories.filter((a) => {
      const ids = [a.id, ...a.aliases].map((x) => x.toUpperCase());
      const hit = active.some((i) => ids.includes(i.id.toUpperCase()) && (!i.package || i.package.toLowerCase() === f.dep.name.toLowerCase()));
      if (hit) ignored++;
      return !hit;
    });
    if (!advisories.length) continue;
    out.push(advisories.length === f.advisories.length ? f : { ...f, advisories, severity: maxSeverity(advisories.map((a) => a.severity)) });
  }
  return { findings: out, ignored, warnings: [...warnings] };
}

/** Test hook: forget cached policies. */
export function clearPolicyCache(): void {
  cache.clear();
}
