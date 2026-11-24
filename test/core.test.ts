import { describe, expect, it } from 'vitest';
import { pickFix, fixCommand } from '../src/core/fix.js';
import { rangesFromEvents, toAdvisory } from '../src/core/osv.js';
import { cvss3Score, osvSeverity } from '../src/core/severity.js';
import { compareVersions, isExactVersion, maxSatisfying } from '../src/core/version.js';
import type { Advisory, Dep } from '../src/types.js';

describe('compareVersions', () => {
  const lt = (a: string, b: string) => expect(compareVersions(a, b), `${a} < ${b}`).toBe(-1);
  it('orders releases and pre-releases', () => {
    lt('1.2.3', '1.2.10');
    lt('1.0.0-rc.1', '1.0.0');
    lt('1.0.0-alpha', '1.0.0-beta');
    lt('1.0a1', '1.0');
    lt('1.0.dev1', '1.0a1');
    lt('1.0', '1.0.post1');
    lt('1.0.post1', '1.0.1');
    lt('v0.3.0', '0.3.7');
    lt('2.14.1', '2.17.0');
    expect(compareVersions('1.0', '1.0.0')).toBe(0);
    expect(compareVersions('2.0.Final', '2.0')).toBe(0);
  });

  it('isExactVersion', () => {
    for (const v of ['1.2.3', 'v1.2.3', '1.0.0-rc.1', '2.10', '1.0.post1', '1.0a1', '0.0.0-20200202094626-16171245cfb2']) expect(isExactVersion(v), v).toBe(true);
    for (const v of ['^1.2.3', '~1.2', '1.x', '>=1', '*', 'latest', '1.2.*', '']) expect(isExactVersion(v), v).toBe(false);
  });

  it('maxSatisfying npm-style ranges', () => {
    const vs = ['0.0.3', '0.0.4', '0.2.0', '0.2.5', '0.3.0', '1.0.0', '1.2.0', '1.9.9', '2.0.0-beta.1', '2.0.0'];
    expect(maxSatisfying(vs, '^1.0.0')).toBe('1.9.9');
    expect(maxSatisfying(vs, '~1.2.0')).toBe('1.2.0');
    expect(maxSatisfying(vs, '^0.2.1')).toBe('0.2.5');
    expect(maxSatisfying(vs, '^0.0.3')).toBe('0.0.3');
    expect(maxSatisfying(vs, '1.x')).toBe('1.9.9');
    expect(maxSatisfying(vs, '*')).toBe('2.0.0');
    expect(maxSatisfying(vs, '>=1.2.0')).toBe('2.0.0');
    expect(maxSatisfying(vs, '1.2.0')).toBe('1.2.0');
    expect(maxSatisfying(vs, '>1 <2 || 3')).toBeUndefined();
  });
});

describe('severity', () => {
  it('computes CVSS 3.1 base scores', () => {
    expect(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
    expect(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
    expect(cvss3Score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(8.1);
    expect(cvss3Score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N')).toBe(3.3);
    expect(cvss3Score('CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe(6.1);
    expect(cvss3Score('CVSS:4.0/AV:N')).toBeUndefined();
  });

  it('prefers the database label over the computed score', () => {
    expect(osvSeverity({ database_specific: { severity: 'MODERATE' }, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] })).toEqual({ severity: 'moderate', score: 9.8 });
    expect(osvSeverity({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }).severity).toBe('critical');
    expect(osvSeverity({}).severity).toBe('unknown');
  });
});

describe('OSV records', () => {
  it('collapses events into ranges', () => {
    expect(rangesFromEvents([{ introduced: '0' }, { fixed: '1.0.1' }, { introduced: '2.0.0' }, { fixed: '2.0.3' }, { introduced: '3.0.0' }])).toEqual([
      { introduced: '0', fixed: '1.0.1' },
      { introduced: '2.0.0', fixed: '2.0.3' },
      { introduced: '3.0.0' },
    ]);
  });

  it('only keeps ranges for the queried package (PyPI names normalised)', () => {
    const v = {
      id: 'PYSEC-1',
      aliases: ['CVE-2023-1', 'GHSA-x'],
      summary: 'Bad',
      affected: [
        { package: { ecosystem: 'PyPI', name: 'Foo_Bar' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.0' }] }] },
        { package: { ecosystem: 'PyPI', name: 'other' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '9' }] }] },
        { package: { ecosystem: 'PyPI', name: 'foo-bar' }, ranges: [{ type: 'GIT', events: [{ introduced: 'abc' }] }] },
      ],
    };
    const a = toAdvisory(v, 'PyPI', 'foo-bar');
    expect(a.ranges).toEqual([{ introduced: '0', fixed: '2.0' }]);
    expect(a.aliases).toEqual(['CVE-2023-1', 'GHSA-x']);
  });
});

describe('fixes', () => {
  const adv = (ranges: Advisory['ranges']): Advisory => ({ id: 'X', aliases: [], summary: '', severity: 'high', ranges, versions: [], references: [] });

  it('picks the nearest fix in the range that contains the version', () => {
    const a = adv([
      { introduced: '0', fixed: '3.0.1' },
      { introduced: '4.0.0', fixed: '4.17.19' },
    ]);
    expect(pickFix('4.17.15', [a])).toEqual({ version: '4.17.19', noFix: false });
    expect(pickFix('2.0.0', [a])).toEqual({ version: '3.0.1', noFix: false });
  });

  it('takes the max across advisories and flags unfixable ones', () => {
    expect(pickFix('1.0.0', [adv([{ introduced: '0', fixed: '1.0.5' }]), adv([{ introduced: '0', fixed: '1.2.0' }])]).version).toBe('1.2.0');
    expect(pickFix('1.0.0', [adv([{ introduced: '0', fixed: '1.0.5' }]), adv([{ introduced: '0' }])]).noFix).toBe(true);
    expect(pickFix('1.0.0', [adv([{ introduced: '0', lastAffected: '1.0.3' }])]).noFix).toBe(true);
  });

  it('builds tool-specific commands', () => {
    const base: Dep = { ecosystem: 'npm', name: 'minimist', version: '0.0.8', direct: false, dev: false, source: 'package-lock.json', tool: 'npm' };
    expect(fixCommand(base, '1.2.6')).toContain('"overrides"');
    expect(fixCommand({ ...base, direct: true, dev: true }, '1.2.6')).toBe('npm install -D minimist@^1.2.6');
    expect(fixCommand({ ...base, ecosystem: 'crates.io', tool: 'cargo', name: 'time' }, '0.2.23')).toBe('cargo update -p time --precise 0.2.23');
    expect(fixCommand({ ...base, ecosystem: 'Go', tool: 'go', name: 'golang.org/x/text' }, '0.3.8')).toBe('go get golang.org/x/text@v0.3.8 && go mod tidy');
  });
});
