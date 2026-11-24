import type { Dep } from '../types.js';
import { viaPaths } from './util.js';

/** "1.13.10-x86_64-linux" -> "1.13.10" (platform-specific gem builds). */
function stripPlatform(v: string): string {
  return v.replace(/-(x86|x64|arm|aarch|universal|java|jruby|mingw|mswin|darwin|linux|musl)[\w.-]*$/i, '');
}

/** Gemfile.lock — the GEM specs section and the DEPENDENCIES section. */
export function parseGemfileLock(text: string, source: string): Dep[] {
  const specs: { name: string; version: string; deps: string[] }[] = [];
  const direct = new Set<string>();
  let section = '';
  let inSpecs = false;
  let cur: (typeof specs)[number] | undefined;

  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim()) continue;
    if (/^\S/.test(raw)) {
      section = raw.trim();
      inSpecs = false;
      continue;
    }
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (section === 'GEM') {
      if (line === 'specs:') {
        inSpecs = true;
        continue;
      }
      if (!inSpecs) continue;
      const m = line.match(/^([^\s(]+)(?:\s+\(([^)]+)\))?$/);
      if (!m) continue;
      if (indent === 4 && m[2]) {
        cur = { name: m[1]!, version: stripPlatform(m[2]), deps: [] };
        specs.push(cur);
      } else if (indent >= 6 && cur) cur.deps.push(m[1]!);
    } else if (section === 'DEPENDENCIES') {
      const m = line.match(/^([^\s(!]+)/);
      if (m) direct.add(m[1]!);
    }
  }
  const graph = new Map(specs.map((s) => [s.name, s.deps] as const));
  const paths = viaPaths(graph, direct);
  const seen = new Set<string>();
  const out: Dep[] = [];
  for (const s of specs) {
    const k = `${s.name}@${s.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const isDirect = direct.has(s.name);
    const via = isDirect ? undefined : paths.get(s.name);
    out.push({ ecosystem: 'RubyGems', name: s.name, version: s.version, direct: isDirect, dev: false, source, tool: 'bundler', ...(via?.length ? { via } : {}) });
  }
  return out;
}
