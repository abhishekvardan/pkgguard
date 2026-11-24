import type { Advisory, Ecosystem, Range } from '../types.js';
import { cacheGet, cacheSet, HOUR } from './cache.js';
import { fetchJson, mapLimit } from './http.js';
import { osvSeverity } from './severity.js';

/** Client for https://osv.dev — free, keyless, covers every ecosystem pkgguard reads. */

const API = process.env.PKGGUARD_OSV_URL || 'https://api.osv.dev';
const BATCH_TTL = 6 * HOUR;
const VULN_TTL = 24 * HOUR;
const BATCH_MAX = 1000;

export interface NetOpts {
  timeoutMs?: number;
  retries?: number;
}

export interface PkgQuery {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
}

/** PEP 503 for PyPI; everything else is case-sensitive as written. */
export function normalizeName(ecosystem: Ecosystem, name: string): string {
  if (ecosystem === 'PyPI') return name.toLowerCase().replace(/[-_.]+/g, '-');
  if (ecosystem === 'NuGet') return name.toLowerCase();
  return name;
}

/** Version string as OSV expects it for the ecosystem. */
export function osvVersion(ecosystem: Ecosystem, version: string): string {
  if (ecosystem === 'Go' || ecosystem === 'Packagist') return version.replace(/^v(?=\d)/, '');
  return version;
}

function key(q: PkgQuery): string {
  return `q|${q.ecosystem}|${normalizeName(q.ecosystem, q.name)}|${q.version ? osvVersion(q.ecosystem, q.version) : '*'}`;
}

function body(q: PkgQuery) {
  return {
    package: { ecosystem: q.ecosystem, name: q.name },
    ...(q.version ? { version: osvVersion(q.ecosystem, q.version) } : {}),
  };
}

/** Vulnerability IDs affecting each query, in the same order. */
export async function queryIds(queries: PkgQuery[], opts: NetOpts = {}): Promise<string[][]> {
  const out: string[][] = new Array(queries.length);
  const misses: number[] = [];
  queries.forEach((q, i) => {
    const hit = cacheGet<string[]>(key(q), BATCH_TTL);
    if (hit) out[i] = hit;
    else misses.push(i);
  });

  for (let start = 0; start < misses.length; start += BATCH_MAX) {
    const chunk = misses.slice(start, start + BATCH_MAX);
    const res = await fetchJson<any>(`${API}/v1/querybatch`, {
      ...opts,
      method: 'POST',
      body: { queries: chunk.map((i) => body(queries[i]!)) },
    });
    const results: any[] = res?.results ?? [];
    await mapLimit(
      chunk.map((qi, j) => [qi, j] as const),
      4,
      async ([qi, j]) => {
        const r = results[j] ?? {};
        const ids: string[] = (r.vulns ?? []).map((v: any) => v.id);
        let token: string | undefined = r.next_page_token;
        // Rare: a package with more results than one page.
        while (token) {
          const page = await fetchJson<any>(`${API}/v1/query`, {
            ...opts,
            method: 'POST',
            body: { ...body(queries[qi]!), page_token: token },
          });
          ids.push(...(page?.vulns ?? []).map((v: any) => v.id));
          token = page?.next_page_token;
        }
        out[qi] = [...new Set(ids)];
        cacheSet(key(queries[qi]!), out[qi]);
      },
    );
  }
  return out;
}

/** Full OSV records, keyed by ID. Unknown IDs are simply absent. */
export async function getVulns(ids: string[], opts: NetOpts = {}): Promise<Map<string, any>> {
  const map = new Map<string, any>();
  const unique = [...new Set(ids)];
  await mapLimit(unique, 8, async (id) => {
    const ck = `v|${id}`;
    let v = cacheGet<any>(ck, VULN_TTL);
    if (!v) {
      v = await fetchJson<any>(`${API}/v1/vulns/${encodeURIComponent(id)}`, opts);
      if (v) cacheSet(ck, v);
    }
    if (v) map.set(id, v);
  });
  return map;
}

function matches(affected: any, ecosystem: Ecosystem, name: string): boolean {
  const pkg = affected?.package;
  if (!pkg) return false;
  if (String(pkg.ecosystem).split(':')[0] !== ecosystem) return false;
  return normalizeName(ecosystem, String(pkg.name)) === normalizeName(ecosystem, name);
}

/** Collapse OSV range events into [introduced, fixed | last_affected) intervals. */
export function rangesFromEvents(events: any[]): Range[] {
  const out: Range[] = [];
  let cur: Range | undefined;
  for (const e of events ?? []) {
    if (e.introduced !== undefined) {
      if (cur) out.push(cur);
      cur = { introduced: String(e.introduced) };
    } else if (e.fixed !== undefined) {
      out.push({ ...(cur ?? {}), fixed: String(e.fixed) });
      cur = undefined;
    } else if (e.last_affected !== undefined) {
      out.push({ ...(cur ?? {}), lastAffected: String(e.last_affected) });
      cur = undefined;
    }
  }
  if (cur) out.push(cur);
  return out;
}

/** The parts of an OSV record that concern one package. */
export function toAdvisory(vuln: any, ecosystem: Ecosystem, name: string): Advisory {
  const ranges: Range[] = [];
  const versions: string[] = [];
  for (const a of vuln.affected ?? []) {
    if (!matches(a, ecosystem, name)) continue;
    for (const r of a.ranges ?? []) {
      if (r.type === 'GIT') continue;
      ranges.push(...rangesFromEvents(r.events));
    }
    versions.push(...(a.versions ?? []).map(String));
  }
  const { severity, score } = osvSeverity(vuln);
  const refs: any[] = vuln.references ?? [];
  const ordered = [...refs.filter((r) => r.type === 'ADVISORY'), ...refs.filter((r) => r.type !== 'ADVISORY')];
  return {
    id: vuln.id,
    aliases: (vuln.aliases ?? []).filter((a: string) => a !== vuln.id),
    summary: (vuln.summary || String(vuln.details ?? '').split('\n')[0] || '').trim().slice(0, 200),
    severity,
    score,
    ranges,
    versions,
    published: vuln.published,
    references: [...new Set(ordered.map((r) => String(r.url)))].slice(0, 5),
  };
}

/** Advisories (withdrawn ones removed) for each query, in the same order. */
export async function advisoriesFor(queries: PkgQuery[], opts: NetOpts = {}): Promise<Advisory[][]> {
  const ids = await queryIds(queries, opts);
  const vulns = await getVulns(ids.flat(), opts);
  return queries.map((q, i) =>
    (ids[i] ?? [])
      .map((id) => vulns.get(id))
      .filter((v) => v && !v.withdrawn)
      .map((v) => toAdvisory(v, q.ecosystem, q.name)),
  );
}
