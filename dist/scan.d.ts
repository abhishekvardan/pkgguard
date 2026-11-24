import type { Dep, Finding, ScanResult, Severity } from './types.js';
import { type NetOpts } from './core/osv.js';
export interface ScanOpts extends NetOpts {
    includeDev?: boolean;
    minSeverity?: Severity;
    /** Skip the extra OSV round-trips that verify suggested safe versions. */
    skipSafeVersions?: boolean;
}
/** Merge duplicates (same package+version from several lockfiles / workspaces). */
export declare function dedupe(deps: Dep[]): Dep[];
/** Check a list of dependencies against OSV and build findings (no filtering). */
export declare function checkDeps(deps: Dep[], opts?: ScanOpts): Promise<Finding[]>;
export declare function sortFindings(findings: Finding[]): Finding[];
export declare function filterFindings(findings: Finding[], min: Severity, includeDev: boolean): Finding[];
export declare function scanProject(root: string, opts?: ScanOpts): Promise<ScanResult>;
