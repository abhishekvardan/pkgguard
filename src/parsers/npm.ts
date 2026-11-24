import type { Dep, Tool } from '../types.js';
import { isExactVersion } from '../core/version.js';
import { parseSimpleYaml, readJson, unquote, viaPaths } from './util.js';

interface Manifest {
  deps: Set<string>;
  dev: Set<string>;
}

/** Direct and dev dependency names from a package.json (empty if absent / unreadable). */
export function readPackageJson(text: string | undefined): Manifest & { raw: any } {
  const m: Manifest & { raw: any } = { deps: new Set(), dev: new Set(), raw: {} };
  if (!text) return m;
  try {
    const j = readJson(text);
    m.raw = j;
    for (const k of Object.keys(j.dependencies ?? {})) m.deps.add(k);
    for (const k of Object.keys(j.optionalDependencies ?? {})) m.deps.add(k);
    for (const k of Object.keys(j.peerDependencies ?? {})) m.deps.add(k);
    for (const k of Object.keys(j.devDependencies ?? {})) if (!m.deps.has(k)) m.dev.add(k);
  } catch {
    // ignore
  }
  return m;
}

function finish(
  entries: { name: string; version: string; dev?: boolean; children: string[] }[],
  manifest: Manifest,
  source: string,
  tool: Tool,
  extraRoots: string[] = [],
): Dep[] {
  const graph = new Map<string, Set<string>>();
  for (const e of entries) {
    const set = graph.get(e.name) ?? new Set<string>();
    e.children.forEach((c) => set.add(c));
    graph.set(e.name, set);
  }
  const roots = [...manifest.deps, ...manifest.dev, ...extraRoots];
  const paths = viaPaths(graph, roots);
  const devOnly = viaPaths(graph, [...manifest.dev]);
  const prodReach = viaPaths(graph, [...manifest.deps, ...extraRoots]);
  const seen = new Set<string>();
  const out: Dep[] = [];
  for (const e of entries) {
    if (!e.version || !isExactVersion(e.version)) continue;
    const k = `${e.name}@${e.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const direct = manifest.deps.has(e.name) || manifest.dev.has(e.name);
    const dev = e.dev ?? (manifest.dev.has(e.name) || (devOnly.has(e.name) && !prodReach.has(e.name)));
    const via = direct ? undefined : paths.get(e.name);
    out.push({ ecosystem: 'npm', name: e.name, version: e.version, direct, dev, source, tool, ...(via?.length ? { via } : {}) });
  }
  return out;
}

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3. */
export function parsePackageLock(text: string, source: string, pkgJson?: string): Dep[] {
  const lock = readJson(text);
  const manifest = readPackageJson(pkgJson);
  const entries: { name: string; version: string; dev?: boolean; children: string[] }[] = [];

  if (lock.packages) {
    const root = lock.packages[''] ?? {};
    for (const k of Object.keys(root.dependencies ?? {})) manifest.deps.add(k);
    for (const k of Object.keys(root.optionalDependencies ?? {})) manifest.deps.add(k);
    for (const k of Object.keys(root.devDependencies ?? {})) if (!manifest.deps.has(k)) manifest.dev.add(k);
    for (const [key, p] of Object.entries<any>(lock.packages)) {
      if (!key || p.link || !key.includes('node_modules/')) continue;
      const name = p.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      entries.push({
        name,
        version: p.version,
        dev: p.dev === true || p.devOptional === true ? true : p.dev === false ? false : undefined,
        children: [...Object.keys(p.dependencies ?? {}), ...Object.keys(p.optionalDependencies ?? {})],
      });
    }
    // v2/v3 always mark dev; entries without the flag are prod.
    for (const e of entries) e.dev ??= false;
  } else if (lock.dependencies) {
    const walk = (deps: Record<string, any>) => {
      for (const [name, d] of Object.entries<any>(deps)) {
        if (typeof d.version === 'string' && !/^(file|link|git|github|http)/.test(d.version)) {
          entries.push({ name, version: d.version, dev: d.dev === true, children: Object.keys(d.requires ?? {}) });
        }
        if (d.dependencies) walk(d.dependencies);
      }
    };
    walk(lock.dependencies);
  }
  return finish(entries, manifest, source, 'npm');
}

/** Split "name@version" where name may itself start with "@scope/". */
function splitAt(s: string): [string, string] | undefined {
  const at = s.lastIndexOf('@');
  if (at <= 0) return undefined;
  return [s.slice(0, at), s.slice(at + 1)];
}

/** Strip pnpm peer-suffixes: "1.2.3(react@18.0.0)" / "1.2.3_react@18.0.0" -> "1.2.3". */
function pnpmVersion(v: string): string {
  return v.replace(/\(.*$/, '').replace(/_.*$/, '');
}

/** pnpm-lock.yaml, lockfile versions 5.x, 6.x and 9.x. */
export function parsePnpmLock(text: string, source: string, pkgJson?: string): Dep[] {
  const y = parseSimpleYaml(text);
  const manifest = readPackageJson(pkgJson);
  const extraRoots: string[] = [];

  const importers: Record<string, any> = y.importers ?? { '.': y };
  for (const imp of Object.values<any>(importers)) {
    for (const k of Object.keys(imp?.dependencies ?? {})) manifest.deps.add(k);
    for (const k of Object.keys(imp?.optionalDependencies ?? {})) manifest.deps.add(k);
    for (const k of Object.keys(imp?.devDependencies ?? {})) if (!manifest.deps.has(k)) manifest.dev.add(k);
  }

  const entries: { name: string; version: string; dev?: boolean; children: string[] }[] = [];
  const v5 = Number.parseFloat(String(y.lockfileVersion ?? '9')) < 6;
  const parseKey = (rawKey: string): [string, string] | undefined => {
    let k = unquote(rawKey).replace(/^\//, '');
    if (v5) {
      // name/version[_peer@x]: the version is the first path segment that starts with a digit after the name
      const m = k.match(/^((?:@[^/]+\/)?[^/]+)\/(\d[^/_(]*)/);
      return m ? [m[1]!, m[2]!] : undefined;
    }
    k = k.replace(/\(.*$/, ''); // v6/v9 peer suffix
    // v6+/v9: name@version
    const at = splitAt(k);
    if (at && /^\d/.test(at[1])) return [at[0], pnpmVersion(at[1])];
    // v5: name/version[_peers]
    const slash = k.lastIndexOf('/');
    if (slash > 0) return [k.slice(0, slash), pnpmVersion(k.slice(slash + 1))];
    return undefined;
  };

  const blocks = [y.packages ?? {}, y.snapshots ?? {}];
  const byKey = new Map<string, { name: string; version: string; dev?: boolean; children: Set<string> }>();
  for (const block of blocks) {
    for (const [rawKey, p] of Object.entries<any>(block)) {
      const nv = parseKey(rawKey);
      if (!nv) continue;
      const id = `${nv[0]}@${nv[1]}`;
      const e = byKey.get(id) ?? { name: nv[0], version: nv[1], children: new Set<string>() };
      if (p?.dev === true || p?.dev === 'true') e.dev = true;
      else if (p?.dev === false || p?.dev === 'false') e.dev = false;
      for (const c of Object.keys(p?.dependencies ?? {})) e.children.add(c);
      for (const c of Object.keys(p?.optionalDependencies ?? {})) e.children.add(c);
      byKey.set(id, e);
    }
  }
  for (const e of byKey.values()) entries.push({ ...e, children: [...e.children] });
  return finish(entries, manifest, source, 'pnpm', extraRoots);
}

/** yarn.lock — classic (v1) and berry (v2+). */
export function parseYarnLock(text: string, source: string, pkgJson?: string): Dep[] {
  const manifest = readPackageJson(pkgJson);
  const entries: { name: string; version: string; children: string[] }[] = [];
  let cur: { name: string; version: string; children: string[] } | undefined;
  let inDeps = false;
  let skip = false;

  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) {
      if (cur && !skip) entries.push(cur);
      cur = undefined;
      inDeps = false;
      skip = false;
      if (line.startsWith('__metadata')) {
        skip = true;
        continue;
      }
      const first = unquote(line.replace(/:$/, '').split(/,\s*/)[0] ?? '');
      // berry "pkg@patch:pkg@npm%3A1.0.0#..." duplicates the plain entry
      const nv = first.includes('@patch:') ? undefined : splitAt(first);
      if (!nv) {
        skip = true;
        continue;
      }
      const [name, range] = nv;
      // berry protocols that are not registry packages
      if (/^(workspace|link|portal|file|exec|git|github|http|https):/.test(range)) skip = true;
      cur = { name: name.replace(/@npm$/, ''), version: '', children: [] };
      continue;
    }
    if (!cur) continue;
    if (indent <= 2) {
      inDeps = /^(dependencies|optionalDependencies):?$/.test(line);
      const m = line.match(/^version:?\s+"?([^"\s]+)"?$/);
      if (m) cur.version = m[1]!;
      continue;
    }
    if (inDeps) {
      const m = line.match(/^("?)(@?[^"\s:]+)\1:?\s/);
      if (m) cur.children.push(m[2]!);
    }
  }
  if (cur && !skip) entries.push(cur);
  return finish(entries, manifest, source, 'yarn');
}

/** package.json with no lockfile next to it: only exact pins can be checked. */
export function parsePackageJsonOnly(text: string, source: string): { deps: Dep[]; unpinned: number } {
  const j = readJson(text);
  const deps: Dep[] = [];
  let unpinned = 0;
  const add = (obj: Record<string, string> | undefined, dev: boolean) => {
    for (const [name, spec] of Object.entries(obj ?? {})) {
      const v = String(spec).replace(/^=/, '').trim();
      if (isExactVersion(v)) deps.push({ ecosystem: 'npm', name, version: v.replace(/^v/, ''), direct: true, dev, source, tool: 'npm' });
      else unpinned++;
    }
  };
  add(j.dependencies, false);
  add(j.optionalDependencies, false);
  add(j.devDependencies, true);
  return { deps, unpinned };
}
