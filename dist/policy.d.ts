import type { Finding, Severity } from './types.js';
/**
 * Per-repo policy, read from `.pkgguard.json` in the project root or the nearest parent:
 *
 *   { "minSeverity": "moderate", "failOn": "high",
 *     "ignore": [{ "id": "GHSA-…", "reason": "not reachable", "until": "2027-01-31" }] }
 *
 * - minSeverity: threshold for the install/edit warnings (env PKGGUARD_MIN_SEVERITY wins).
 * - failOn: lowest severity that fails `pkgguard scan`, `install`, `watch` (and blocks `add --strict`).
 * - ignore: accepted risks. Matches the advisory id or any alias (CVE). Optional "package" narrows it
 *   to one package. An ignore past its "until" date stops applying, with a warning.
 */
export interface Ignore {
    id: string;
    package?: string;
    reason?: string;
    until?: string;
}
export interface Policy {
    minSeverity?: Severity;
    failOn?: Severity;
    ignore: Ignore[];
    /** Where it was read from. */
    file?: string;
}
export declare const POLICY_FILE = ".pkgguard.json";
/** Find and read the nearest `.pkgguard.json` at or above `root`. Never throws. */
export declare function loadPolicy(root: string): {
    policy: Policy;
    warnings: string[];
};
export declare function parsePolicy(text: string, file?: string): {
    policy: Policy;
    warnings: string[];
};
/** Drop ignored advisories (and findings left with none). Expired ignores don't apply and are reported. */
export declare function applyPolicy(findings: Finding[], policy: Policy, now?: Date): {
    findings: Finding[];
    ignored: number;
    warnings: string[];
};
/** Test hook: forget cached policies. */
export declare function clearPolicyCache(): void;
