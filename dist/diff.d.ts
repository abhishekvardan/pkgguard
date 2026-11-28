import type { Finding } from './types.js';
/**
 * A fingerprint names one advisory on one package version: `npm:lodash@4.17.15#GHSA-p6mc-m468-83gw`.
 * Comparing fingerprint sets tells what is new since an earlier scan — a newly published CVE
 * against a version you already had, or a vulnerable version that an install brought in.
 */
export declare function fingerprint(f: Pick<Finding, 'dep'>, advisoryId: string): string;
export declare function fingerprints(findings: Finding[]): string[];
export interface Diff {
    /** Findings narrowed to their advisories that were not in the baseline. */
    added: Finding[];
    /** Baseline fingerprints that are gone (upgraded, removed, or the advisory was withdrawn). */
    resolved: string[];
    unchanged: number;
}
export declare function diffFindings(baseline: Iterable<string>, findings: Finding[]): Diff;
/** Read a baseline: the output of `pkgguard scan --json` (or any JSON with a `fingerprints` array). */
export declare function readBaseline(file: string): string[];
/** "npm lodash 4.17.15 (GHSA-…)" for a fingerprint. */
export declare function describeFingerprint(fp: string): string;
