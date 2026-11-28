import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import type { Finding, Severity } from '../types.js';
import { cveOf } from '../format.js';
import { fingerprint } from '../diff.js';
import { SEVERITY_RANK } from '../types.js';

/**
 * Durable watcher state (~/.pkgguard/state.json, or PKGGUARD_STATE_DIR). Unlike the cache it is
 * never expired: it remembers, per project, every vulnerable fingerprint and when it was first
 * seen, so a later run (or the next Claude session) can say what is new.
 */

export interface Entry {
  firstSeen: string;
  ecosystem: string;
  name: string;
  version: string;
  advisory: string;
  cve?: string;
  severity: Severity;
  summary: string;
  safeVersion?: string;
  source: string;
}

export interface ProjectState {
  root: string;
  lastScan: string;
  findings: Record<string, Entry>;
}

export interface State {
  version: 1;
  projects: Record<string, ProjectState>;
  /** When a Claude session last started in each project root (for "new since your last session"). */
  sessions: Record<string, string>;
}

export function stateDir(): string {
  return process.env.PKGGUARD_STATE_DIR || join(homedir(), '.pkgguard');
}

const stateFile = () => join(stateDir(), 'state.json');

export const rootKey = (root: string) => resolve(root).replace(/[\\/]+$/, '').toLowerCase();

export function loadState(): State {
  try {
    const s = JSON.parse(readFileSync(stateFile(), 'utf8'));
    if (s?.version === 1) return { version: 1, projects: s.projects ?? {}, sessions: s.sessions ?? {} };
  } catch {
    // missing or corrupt: start over
  }
  return { version: 1, projects: {}, sessions: {} };
}

/** Atomic write, so a session hook and a scheduled watch can't leave half a file. */
export function saveState(s: State): void {
  mkdirSync(stateDir(), { recursive: true });
  const tmp = `${stateFile()}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(s, null, 1));
  renameSync(tmp, stateFile());
}

export function entriesOf(findings: Finding[], now: string): Record<string, Entry> {
  const out: Record<string, Entry> = {};
  for (const f of findings) {
    for (const a of f.advisories) {
      out[fingerprint(f, a.id)] = {
        firstSeen: now,
        ecosystem: f.dep.ecosystem,
        name: f.dep.name,
        version: f.dep.version,
        advisory: a.id,
        cve: cveOf(a),
        severity: a.severity,
        summary: a.summary.slice(0, 160),
        safeVersion: f.safeVersion,
        source: f.dep.source,
      };
    }
  }
  return out;
}

export interface Update {
  /** True when this project had never been recorded: everything is a baseline, nothing is "new". */
  firstRun: boolean;
  added: Entry[];
  resolved: Entry[];
  total: number;
}

/** Record a scan of `root` and report what changed since the previous one. */
export function recordScan(state: State, root: string, findings: Finding[], now = new Date().toISOString()): Update {
  const key = rootKey(root);
  const prev = state.projects[key];
  const current = entriesOf(findings, now);
  const added: Entry[] = [];
  for (const [fp, e] of Object.entries(current)) {
    const old = prev?.findings[fp];
    if (old) current[fp] = { ...e, firstSeen: old.firstSeen };
    else if (prev) added.push(e);
  }
  const resolved = prev ? Object.entries(prev.findings).filter(([fp]) => !current[fp]).map(([, e]) => e) : [];
  state.projects[key] = { root: resolve(root), lastScan: now, findings: current };
  return { firstRun: !prev, added: sortEntries(added), resolved: sortEntries(resolved), total: Object.keys(current).length };
}

export function sortEntries(e: Entry[]): Entry[] {
  return e.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.name.localeCompare(b.name));
}

/**
 * Entries first seen after `since`, across `root` and every recorded project inside it
 * (a watch of a parent folder records each repo separately). Deduped by fingerprint, keeping
 * the earliest sighting.
 */
export function newSince(state: State, root: string, since: string): Entry[] {
  const key = rootKey(root);
  const best = new Map<string, Entry>();
  for (const [k, p] of Object.entries(state.projects)) {
    if (k !== key && !k.startsWith(key + sep.toLowerCase()) && !k.startsWith(key + '/')) continue;
    for (const [fp, e] of Object.entries(p.findings)) {
      const prev = best.get(fp);
      if (!prev || e.firstSeen < prev.firstSeen) best.set(fp, e);
    }
  }
  return sortEntries([...best.values()].filter((e) => e.firstSeen > since));
}

/** Group entries by package version: one line per package, the advisories joined. */
export function groupEntries(entries: Entry[]): { key: string; head: Entry; ids: string[] }[] {
  const groups = new Map<string, { key: string; head: Entry; ids: string[] }>();
  for (const e of entries) {
    const key = `${e.ecosystem}|${e.name}|${e.version}`;
    const g = groups.get(key);
    const id = e.cve ?? e.advisory;
    if (!g) groups.set(key, { key, head: e, ids: [id] });
    else if (!g.ids.includes(id)) g.ids.push(id);
  }
  return [...groups.values()];
}

export function formatEntries(entries: Entry[], limit = 8): string[] {
  const groups = groupEntries(entries);
  const lines = groups.slice(0, limit).map(({ head: e, ids }) => {
    const more = ids.length > 2 ? ` +${ids.length - 2} more` : '';
    const fix = e.safeVersion ? ` → ${e.safeVersion}` : '';
    return `- ${e.name}@${e.version} [${e.severity}] ${ids.slice(0, 2).join(', ')}${more}: ${e.summary}${fix} (${e.source})`;
  });
  if (groups.length > limit) lines.push(`- …and ${groups.length - limit} more`);
  return lines;
}

export const hasState = () => existsSync(stateFile());
