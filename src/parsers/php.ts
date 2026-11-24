import type { Dep } from '../types.js';
import { readJson, viaPaths } from './util.js';

const platform = (n: string) => n === 'php' || n.startsWith('ext-') || n.startsWith('lib-') || n === 'composer-plugin-api' || !n.includes('/');

/** composer.lock (+ composer.json beside it for direct dependencies). */
export function parseComposerLock(text: string, source: string, composerJson?: string): Dep[] {
  const lock = readJson(text);
  let direct = new Set<string>();
  let directDev = new Set<string>();
  if (composerJson) {
    try {
      const j = readJson(composerJson);
      direct = new Set(Object.keys(j.require ?? {}).map((n) => n.toLowerCase()));
      directDev = new Set(Object.keys(j['require-dev'] ?? {}).map((n) => n.toLowerCase()));
    } catch {
      // ignore
    }
  }
  const all: { p: any; dev: boolean }[] = [
    ...(lock.packages ?? []).map((p: any) => ({ p, dev: false })),
    ...(lock['packages-dev'] ?? []).map((p: any) => ({ p, dev: true })),
  ];
  const graph = new Map<string, string[]>();
  for (const { p } of all) graph.set(String(p.name).toLowerCase(), Object.keys(p.require ?? {}).map((n) => n.toLowerCase()));
  const paths = viaPaths(graph, [...direct, ...directDev]);
  const out: Dep[] = [];
  for (const { p, dev } of all) {
    const name = String(p.name);
    const version = String(p.version ?? '').replace(/^v(?=\d)/, '');
    if (platform(name) || !/^\d/.test(version)) continue; // dev-main etc.
    const lower = name.toLowerCase();
    const isDirect = composerJson ? direct.has(lower) || directDev.has(lower) : true;
    const via = isDirect ? undefined : paths.get(lower);
    out.push({ ecosystem: 'Packagist', name, version, direct: isDirect, dev, source, tool: 'composer', ...(via?.length ? { via } : {}) });
  }
  return out;
}
