import type { Severity } from '../types.js';
/** Base score of a CVSS v3.x vector such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. */
export declare function cvss3Score(vector: string): number | undefined;
export declare function severityFromScore(score: number): Severity;
/** Normalise the labels different databases use (GHSA "MODERATE", PyPA "MEDIUM", …). */
export declare function severityFromLabel(label: unknown): Severity | undefined;
/**
 * Severity of an OSV record. Prefers the database's own label (GitHub's reviewed rating),
 * then a computed CVSS v3 score. CVSS v4 vectors are not computed; they rarely appear
 * without a label alongside.
 */
export declare function osvSeverity(vuln: any): {
    severity: Severity;
    score?: number;
};
export declare function maxSeverity(list: Severity[]): Severity;
export declare function atLeast(sev: Severity, min: Severity): boolean;
export declare function parseSeverity(s: string | undefined, fallback: Severity): Severity;
