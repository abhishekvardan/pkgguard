import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Advisory, Finding, Severity } from '../src/types.js';
import { applyPolicy, clearPolicyCache, loadPolicy, parsePolicy } from '../src/policy.js';
import { diffFindings, fingerprint, fingerprints, readBaseline } from '../src/diff.js';
import { detectIn, detectManager } from '../src/pm/detect.js';
import { parseSpec, planItems } from '../src/pm/add.js';
import { addCommands, specFor, syncCommand } from '../src/pm/run.js';
import { cronLine, parseInterval, schtasksArgs } from '../src/watch/schedule.js';
import { newSince, recordScan, type State } from '../src/watch/state.js';
import { findProjects } from '../src/watch/watch.js';

const adv = (id: string, severity: Severity = 'high', cve?: string): Advisory => ({
  id,
  aliases: cve ? [cve] : [],
  summary: `summary of ${id}`,
  severity,
  ranges: [{ introduced: '0', fixed: '9.9.9' }],
  versions: [],
  references: [],
});

const finding = (name: string, version: string, advisories: Advisory[], safeVersion?: string): Finding => ({
  dep: { ecosystem: 'npm', name, version, direct: true, dev: false, source: 'package-lock.json', tool: 'npm' },
  advisories,
  severity: advisories[0]?.severity ?? 'high',
  safeVersion,
  noFix: !safeVersion,
});

const tmp = () => mkdtempSync(join(tmpdir(), 'pkgguard-'));

describe('policy', () => {
  it('ignores by id or alias, optionally per package', () => {
    const { policy } = parsePolicy(JSON.stringify({ ignore: [{ id: 'CVE-1' }, { id: 'GHSA-b', package: 'other' }] }));
    const r = applyPolicy([finding('a', '1.0.0', [adv('GHSA-a', 'high', 'CVE-1'), adv('GHSA-b', 'low')])], policy);
    expect(r.ignored).toBe(1);
    expect(r.findings[0]!.advisories.map((a) => a.id)).toEqual(['GHSA-b']);
    expect(r.findings[0]!.severity).toBe('low');
  });

  it('stops applying an ignore after its date, with a warning', () => {
    const { policy } = parsePolicy(JSON.stringify({ ignore: [{ id: 'GHSA-a', until: '2026-01-31' }] }));
    const f = [finding('a', '1.0.0', [adv('GHSA-a')])];
    expect(applyPolicy(f, policy, new Date('2026-01-31T20:00:00Z')).findings).toHaveLength(0); // the whole last day counts
    const later = applyPolicy(f, policy, new Date('2026-02-02T00:00:00Z'));
    expect(later.findings).toHaveLength(1);
    expect(later.warnings[0]).toMatch(/expired on 2026-01-31/);
  });

  it('reads severities and reports mistakes', () => {
    const r = parsePolicy(JSON.stringify({ failOn: 'critical', minSeverity: 'severe', ignore: [{ reason: 'x' }] }));
    expect(r.policy.failOn).toBe('critical');
    expect(r.policy.minSeverity).toBeUndefined();
    expect(r.warnings).toHaveLength(2);
    expect(parsePolicy('{oops').warnings[0]).toMatch(/not valid JSON/);
  });

  it('finds the nearest .pkgguard.json but stops at a repository root', () => {
    clearPolicyCache();
    const root = tmp();
    writeFileSync(join(root, '.pkgguard.json'), '{"failOn":"critical"}');
    mkdirSync(join(root, 'app', 'sub'), { recursive: true });
    expect(loadPolicy(join(root, 'app', 'sub')).policy.failOn).toBe('critical');
    mkdirSync(join(root, 'repo', '.git'), { recursive: true });
    expect(loadPolicy(join(root, 'repo')).policy.failOn).toBeUndefined();
  });
});

describe('diff', () => {
  it('reports only advisories that are new, and what was resolved', () => {
    const before = [finding('a', '1.0.0', [adv('GHSA-1')]), finding('b', '2.0.0', [adv('GHSA-2')])];
    const now = [finding('a', '1.0.0', [adv('GHSA-1'), adv('GHSA-3', 'critical')])];
    const d = diffFindings(fingerprints(before), now);
    expect(d.added).toHaveLength(1);
    expect(d.added[0]!.advisories.map((a) => a.id)).toEqual(['GHSA-3']);
    expect(d.added[0]!.severity).toBe('critical');
    expect(d.resolved).toEqual([fingerprint(before[1]!, 'GHSA-2')]);
    expect(d.unchanged).toBe(1);
  });

  it('reads a baseline from scan --json output', () => {
    const dir = tmp();
    const file = join(dir, 'base.json');
    writeFileSync(file, JSON.stringify({ findings: [{ ecosystem: 'npm', name: 'a', version: '1.0.0', advisories: [{ id: 'GHSA-1' }] }] }));
    expect(readBaseline(file)).toEqual(['npm:a@1.0.0#GHSA-1']);
    writeFileSync(file, JSON.stringify({ fingerprints: ['x'] }));
    expect(readBaseline(file)).toEqual(['x']);
  });
});

describe('package manager detection', () => {
  it('prefers the lockfile, then the manifest', () => {
    const d = tmp();
    writeFileSync(join(d, 'package.json'), '{}');
    expect(detectIn(d)).toBe('npm');
    writeFileSync(join(d, 'pnpm-lock.yaml'), '');
    expect(detectIn(d)).toBe('pnpm');
    const p = tmp();
    writeFileSync(join(p, 'package.json'), '{"packageManager":"yarn@4.1.0"}');
    expect(detectIn(p)).toBe('yarn');
    const py = tmp();
    writeFileSync(join(py, 'pyproject.toml'), '[tool.poetry]\nname="x"\n');
    expect(detectIn(py)).toBe('poetry');
    writeFileSync(join(py, 'uv.lock'), '');
    expect(detectIn(py)).toBe('uv');
  });

  it('searches upward and accepts --pm', () => {
    const d = tmp();
    writeFileSync(join(d, 'Cargo.toml'), '');
    mkdirSync(join(d, 'src', 'bin'), { recursive: true });
    expect(detectManager(join(d, 'src', 'bin'))).toEqual({ manager: 'cargo', root: d });
    expect(detectManager(d, 'bundler')!.manager).toBe('bundle');
    expect(() => detectManager(d, 'maven')).toThrow(/Unknown package manager/);
  });
});

describe('pkgguard add', () => {
  it('parses specs per ecosystem', () => {
    expect(parseSpec('npm', 'lodash@4.17.15')).toMatchObject({ name: 'lodash', kind: 'exact', version: '4.17.15' });
    expect(parseSpec('pnpm', '@types/node')).toMatchObject({ name: '@types/node', kind: 'latest', manager: 'pnpm' });
    expect(parseSpec('npm', 'react@^18')).toMatchObject({ kind: 'range', version: '^18' });
    expect(parseSpec('uv', 'requests==2.19.0')).toMatchObject({ ecosystem: 'PyPI', kind: 'exact', version: '2.19.0' });
    expect(parseSpec('go', 'golang.org/x/text@v0.3.0')).toMatchObject({ ecosystem: 'Go', name: 'golang.org/x/text', kind: 'exact', version: '0.3.0' });
    expect(parseSpec('composer', 'guzzlehttp/guzzle:7.4.0')).toMatchObject({ name: 'guzzlehttp/guzzle', kind: 'exact' });
    expect(parseSpec('cargo', 'serde')).toMatchObject({ name: 'serde', kind: 'latest' });
    expect(parseSpec('npm', './local-pkg')).toBeUndefined();
  });

  it('swaps a vulnerable version for the safe one, and refuses when there is none', () => {
    const specs = [
      { original: 'lodash@4.17.15', intent: parseSpec('npm', 'lodash@4.17.15'), resolved: '4.17.15' },
      { original: 'left-pad', intent: parseSpec('npm', 'left-pad'), resolved: '1.3.0' },
    ];
    const ok = planItems(specs, [finding('lodash', '4.17.15', [adv('GHSA-1', 'high', 'CVE-2020-8203')], '4.17.21')]);
    expect(ok.blocked).toHaveLength(0);
    expect(ok.planned.map((p) => p.item)).toEqual([
      { name: 'lodash', version: '4.17.21', original: 'lodash@4.17.15', changed: true },
      { name: 'left-pad', version: undefined, original: 'left-pad', changed: false },
    ]);
    expect(ok.notes[0]).toMatch(/installing lodash@4\.17\.21 instead/);

    const none = planItems(specs.slice(0, 1), [finding('lodash', '4.17.15', [adv('GHSA-1')])]);
    expect(none.blocked).toHaveLength(1);
    expect(none.notes[0]).toMatch(/Refusing/);
    expect(planItems(specs.slice(0, 1), [finding('lodash', '4.17.15', [adv('GHSA-1')])], true).blocked).toHaveLength(0);
  });

  it('writes each manager\'s own install command', () => {
    const it1 = { name: 'lodash', version: '4.17.21', original: 'lodash@4.17.15', changed: true };
    expect(addCommands('npm', [it1], true)).toEqual([{ cmd: 'npm', args: ['install', '-D', 'lodash@4.17.21'] }]);
    expect(specFor('uv', { ...it1, name: 'requests', version: '2.32.0' })).toBe('requests>=2.32.0');
    expect(specFor('poetry', { ...it1, version: '2.0.0' })).toBe('lodash@^2.0.0');
    expect(specFor('go', { name: 'golang.org/x/text', version: '0.3.8', original: 'golang.org/x/text', changed: true })).toBe('golang.org/x/text@v0.3.8');
    expect(specFor('go', { name: 'golang.org/x/text', original: 'golang.org/x/text', changed: false })).toBe('golang.org/x/text@latest');
    expect(addCommands('bundle', [{ name: 'rails', version: '7.1.3', original: 'rails', changed: true }], false)[0]!.args).toEqual(['add', 'rails', '--version', '~> 7.1.3']);
    expect(addCommands('dotnet', [it1, { ...it1, name: 'B' }], false)).toHaveLength(2);
    const d = tmp();
    writeFileSync(join(d, 'package-lock.json'), '{}');
    expect(syncCommand('npm', d, true)).toEqual({ cmd: 'npm', args: ['ci'] });
    expect(syncCommand('pip', tmp())).toBeUndefined();
  });
});

describe('watcher state', () => {
  it('records a baseline, then reports new and resolved advisories', () => {
    const s: State = { version: 1, projects: {}, sessions: {} };
    const first = recordScan(s, '/repo', [finding('a', '1.0.0', [adv('GHSA-1')])], '2026-11-01T00:00:00.000Z');
    expect(first.firstRun).toBe(true);
    expect(first.added).toHaveLength(0);
    const next = recordScan(s, '/repo', [finding('a', '1.0.0', [adv('GHSA-1'), adv('GHSA-2', 'critical', 'CVE-9')])], '2026-11-02T00:00:00.000Z');
    expect(next.added.map((e) => e.advisory)).toEqual(['GHSA-2']);
    expect(next.added[0]!.cve).toBe('CVE-9');
    const fixed = recordScan(s, '/repo', [], '2026-11-03T00:00:00.000Z');
    expect(fixed.resolved).toHaveLength(2);
  });

  it('newSince looks inside sub-projects and keeps the earliest sighting', () => {
    const s: State = { version: 1, projects: {}, sessions: {} };
    recordScan(s, '/work/app', [finding('a', '1.0.0', [adv('GHSA-1')])], '2026-11-01T00:00:00.000Z');
    recordScan(s, '/work/app', [finding('a', '1.0.0', [adv('GHSA-1'), adv('GHSA-2')])], '2026-11-05T00:00:00.000Z');
    expect(newSince(s, '/work', '2026-11-03T00:00:00.000Z').map((e) => e.advisory)).toEqual(['GHSA-2']);
    expect(newSince(s, '/elsewhere', '2026-01-01T00:00:00.000Z')).toHaveLength(0);
  });

  it('finds projects: git repos and folders with dependency files', () => {
    const root = tmp();
    mkdirSync(join(root, 'a', '.git'), { recursive: true });
    mkdirSync(join(root, 'group', 'b'), { recursive: true });
    writeFileSync(join(root, 'group', 'b', 'package.json'), '{}');
    mkdirSync(join(root, 'node_modules', 'x'), { recursive: true });
    writeFileSync(join(root, 'node_modules', 'x', 'package.json'), '{}');
    expect(findProjects(root).map((p) => p.slice(root.length + 1).replace(/\\/g, '/')).sort()).toEqual(['a', 'group/b']);
  });
});

describe('schedule', () => {
  it('parses intervals and builds the commands', () => {
    expect(parseInterval('6h')).toEqual({ unit: 'hour', n: 6 });
    expect(parseInterval('30m')).toEqual({ unit: 'minute', n: 30 });
    expect(parseInterval('1 day')).toEqual({ unit: 'day', n: 1 });
    expect(() => parseInterval('5m')).toThrow(/15 minutes/);
    expect(() => parseInterval('48h')).toThrow(/1–23/);
    expect(schtasksArgs({ unit: 'hour', n: 6 }, 'C:\\x\\watch.vbs')).toEqual([
      '/Create', '/TN', 'pkgguard watch', '/SC', 'HOURLY', '/MO', '6', '/TR', 'wscript.exe //B //Nologo "C:\\x\\watch.vbs"', '/F',
    ]);
    expect(cronLine({ unit: 'hour', n: 6 }, 'cmd')).toBe('0 */6 * * * cmd');
    expect(cronLine({ unit: 'minute', n: 30 }, 'cmd')).toBe('*/30 * * * * cmd');
  });
});
