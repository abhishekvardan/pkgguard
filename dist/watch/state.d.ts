import type { Finding, Severity } from '../types.js';
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
export declare function stateDir(): string;
export declare const rootKey: (root: string) => string;
export declare function loadState(): State;
/** Atomic write, so a session hook and a scheduled watch can't leave half a file. */
export declare function saveState(s: State): void;
export declare function entriesOf(findings: Finding[], now: string): Record<string, Entry>;
export interface Update {
    /** True when this project had never been recorded: everything is a baseline, nothing is "new". */
    firstRun: boolean;
    added: Entry[];
    resolved: Entry[];
    total: number;
}
/** Record a scan of `root` and report what changed since the previous one. */
export declare function recordScan(state: State, root: string, findings: Finding[], now?: string): Update;
export declare function sortEntries(e: Entry[]): Entry[];
/**
 * Entries first seen after `since`, across `root` and every recorded project inside it
 * (a watch of a parent folder records each repo separately). Deduped by fingerprint, keeping
 * the earliest sighting.
 */
export declare function newSince(state: State, root: string, since: string): Entry[];
/** Group entries by package version: one line per package, the advisories joined. */
export declare function groupEntries(entries: Entry[]): {
    key: string;
    head: Entry;
    ids: string[];
}[];
export declare function formatEntries(entries: Entry[], limit?: number): string[];
export declare const hasState: () => boolean;
