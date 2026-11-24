import type { Advisory, Dep, Finding } from '../types.js';
import { type NetOpts } from './osv.js';
/**
 * The smallest version above `current` that is outside every advisory's affected range.
 * Picking the nearest fix per advisory keeps the upgrade within the same major whenever
 * the maintainers backported one.
 */
export declare function pickFix(current: string, advisories: Advisory[]): {
    version?: string;
    noFix: boolean;
};
/**
 * Fill in `safeVersion` on every finding: propose a fix, ask OSV whether that version is
 * itself affected by something else, and step forward again if so (at most 4 rounds).
 */
export declare function resolveSafeVersions(findings: Finding[], opts?: NetOpts): Promise<void>;
/** The command (or edit) that moves this dependency to `safe`. */
export declare function fixCommand(dep: Dep, safe: string): string;
