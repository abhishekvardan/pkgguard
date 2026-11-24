import type { Dep } from '../types.js';
import { isExactVersion } from '../core/version.js';
import { readJson } from './util.js';

/** packages.lock.json (NuGet lock file). */
export function parseNugetLock(text: string, source: string): Dep[] {
  const j = readJson(text);
  const out: Dep[] = [];
  const seen = new Set<string>();
  for (const framework of Object.values<any>(j.dependencies ?? {})) {
    for (const [name, d] of Object.entries<any>(framework ?? {})) {
      if (d?.type === 'Project' || !d?.resolved) continue;
      const k = `${name.toLowerCase()}@${d.resolved}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ ecosystem: 'NuGet', name, version: String(d.resolved), direct: d.type === 'Direct', dev: false, source, tool: 'nuget' });
    }
  }
  return out;
}

/**
 * *.csproj / *.fsproj / *.vbproj / Directory.Packages.props — PackageReference and
 * PackageVersion items with a literal version.
 */
export function parseMsbuild(text: string, source: string): { deps: Dep[]; unpinned: number } {
  const out: Dep[] = [];
  let unpinned = 0;
  const re = /<(PackageReference|PackageVersion)\b([^>]*?)(\/>|>([\s\S]*?)<\/\1>)/g;
  for (const m of text.matchAll(re)) {
    const attrs = m[2] ?? '';
    const inner = m[4] ?? '';
    const name = attrs.match(/\b(?:Include|Update)\s*=\s*"([^"]+)"/)?.[1];
    const version = attrs.match(/\bVersion\s*=\s*"([^"]+)"/)?.[1] ?? inner.match(/<Version>\s*([^<\s]+)\s*<\/Version>/)?.[1];
    if (!name) continue;
    if (!version) continue; // version comes from central management
    const v = version.replace(/^\[([^,\]]+)\]$/, '$1'); // [1.2.3] exact-range notation
    if (!isExactVersion(v) || v.includes('$(')) {
      unpinned++;
      continue;
    }
    const dev = /PrivateAssets\s*=\s*"all"/i.test(attrs) || /<PrivateAssets>\s*all/i.test(inner);
    out.push({ ecosystem: 'NuGet', name, version: v, direct: true, dev, source, tool: 'nuget' });
  }
  return { deps: out, unpinned };
}
