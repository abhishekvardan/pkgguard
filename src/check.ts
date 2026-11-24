import type { Dep, Ecosystem, Finding, Tool } from './types.js';
import { advisoriesFor, getVulns, toAdvisory, type NetOpts } from './core/osv.js';
import { latestVersion } from './core/registry.js';
import { compareVersions } from './core/version.js';
import { advisoryTitle, findingJson, formatAdvisory, formatFinding, rangeText } from './format.js';
import { checkDeps } from './scan.js';

const ALIASES: Record<string, Ecosystem> = {
  npm: 'npm', node: 'npm', nodejs: 'npm', js: 'npm', javascript: 'npm', typescript: 'npm', yarn: 'npm', pnpm: 'npm', bun: 'npm',
  pypi: 'PyPI', python: 'PyPI', pip: 'PyPI', poetry: 'PyPI', uv: 'PyPI', pipenv: 'PyPI',
  go: 'Go', golang: 'Go',
  'crates.io': 'crates.io', crates: 'crates.io', cargo: 'crates.io', rust: 'crates.io',
  maven: 'Maven', java: 'Maven', gradle: 'Maven', kotlin: 'Maven',
  rubygems: 'RubyGems', gem: 'RubyGems', gems: 'RubyGems', ruby: 'RubyGems', bundler: 'RubyGems',
  packagist: 'Packagist', composer: 'Packagist', php: 'Packagist',
  nuget: 'NuGet', dotnet: 'NuGet', '.net': 'NuGet', csharp: 'NuGet',
};

export function parseEcosystem(s: string): Ecosystem | undefined {
  return ALIASES[s.trim().toLowerCase()];
}

export const DEFAULT_TOOL: Record<Ecosystem, Tool> = {
  npm: 'npm',
  PyPI: 'pip',
  Go: 'go',
  'crates.io': 'cargo',
  Maven: 'maven',
  RubyGems: 'bundler',
  Packagist: 'composer',
  NuGet: 'nuget',
};

export interface CheckResult {
  text: string;
  json: any;
}

/** Is name@version vulnerable? Without a version: its history and whether the latest release is clean. */
export async function checkPackage(ecosystem: Ecosystem, name: string, version: string | undefined, opts: NetOpts = {}): Promise<CheckResult> {
  if (version) {
    const dep: Dep = { ecosystem, name, version, direct: true, dev: false, source: 'query', tool: DEFAULT_TOOL[ecosystem] };
    const [f] = await checkDeps([dep], opts);
    if (!f) return { text: `${ecosystem} ${name}@${version}: no known vulnerabilities (OSV.dev).`, json: { ecosystem, name, version, vulnerable: false } };
    return { text: formatFinding(f, 10).replace(/ — query$/m, ''), json: { vulnerable: true, ...findingJson(f) } };
  }

  const [all = [], latest] = await Promise.all([
    advisoriesFor([{ ecosystem, name }], opts).then((r) => r[0]),
    latestVersion(ecosystem, name, opts),
  ]);
  let latestFinding: Finding | undefined;
  if (latest) {
    const dep: Dep = { ecosystem, name, version: latest, direct: true, dev: false, source: 'query', tool: DEFAULT_TOOL[ecosystem] };
    [latestFinding] = await checkDeps([dep], { ...opts, skipSafeVersions: true });
  }
  const lines: string[] = [];
  lines.push(
    latest
      ? latestFinding
        ? `${ecosystem} ${name}: latest release ${latest} is AFFECTED by ${latestFinding.advisories.length} advisory(ies) — ${latestFinding.advisories.map(advisoryTitle).join(', ')}.`
        : `${ecosystem} ${name}: latest release ${latest} has no known vulnerabilities.`
      : `${ecosystem} ${name}: could not look up the latest release.`,
  );
  if (!all.length) lines.push('No advisories have ever been published for this package.');
  else {
    lines.push(`${all.length} advisory(ies) on record — avoid these versions:`);
    const sorted = [...all].sort((a, b) => (b.published ?? '').localeCompare(a.published ?? ''));
    for (const a of sorted.slice(0, 20)) {
      const ranges = a.ranges.length ? a.ranges.map(rangeText).join(' | ') : `${a.versions.length} listed versions`;
      lines.push(`- ${advisoryTitle(a)} [${a.severity}] affected: ${ranges} — ${a.summary}`);
    }
    if (sorted.length > 20) lines.push(`- …and ${sorted.length - 20} older advisories`);
  }
  const fixed = all.flatMap((a) => a.ranges.map((r) => r.fixed)).filter((x): x is string => !!x);
  return {
    text: lines.join('\n'),
    json: {
      ecosystem,
      name,
      latest: latest ?? null,
      latestVulnerable: latest ? !!latestFinding : null,
      highestFixedVersion: fixed.sort(compareVersions).at(-1) ?? null,
      advisories: all.map((a) => ({ id: a.id, severity: a.severity, summary: a.summary, affected: a.ranges.map(rangeText) })),
    },
  };
}

export async function getVulnerability(id: string, opts: NetOpts = {}): Promise<CheckResult | undefined> {
  const tries = [...new Set([id.trim(), id.trim().toUpperCase()])];
  for (const t of tries) {
    const v = (await getVulns([t], opts)).get(t);
    if (!v) continue;
    const pkgs = (v.affected ?? []).filter((a: any) => a.package?.name && a.package?.ecosystem);
    const lines: string[] = [];
    const first = pkgs[0];
    const base = toAdvisory(v, first?.package?.ecosystem ?? 'npm', first?.package?.name ?? '');
    lines.push(formatAdvisory({ ...base, ranges: [] }));
    for (const a of pkgs.slice(0, 15)) {
      const adv = toAdvisory(v, String(a.package.ecosystem).split(':')[0] as Ecosystem, a.package.name);
      lines.push(`Affected ${a.package.ecosystem} ${a.package.name}: ${adv.ranges.length ? adv.ranges.map(rangeText).join(' | ') : `${adv.versions.length} listed versions`}`);
    }
    if (v.withdrawn) lines.push(`WITHDRAWN on ${String(v.withdrawn).slice(0, 10)} — no longer considered a vulnerability.`);
    const details = String(v.details ?? '').trim();
    if (details) lines.push('', details.length > 1500 ? `${details.slice(0, 1500)}…` : details);
    return { text: lines.join('\n'), json: v };
  }
  return undefined;
}
