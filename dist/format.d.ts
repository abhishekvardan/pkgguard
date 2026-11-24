import type { Advisory, Finding, Range, ScanResult, Severity } from './types.js';
export declare function cveOf(a: Advisory): string | undefined;
export declare function advisoryTitle(a: Advisory): string;
export declare function rangeText(r: Range): string;
export declare function countBySeverity(findings: Finding[]): string;
/** Multi-line description of one finding. */
export declare function formatFinding(f: Finding, maxAdvisories?: number): string;
export declare function formatScan(r: ScanResult, limit?: number): string;
/** One-line-per-package summary, for hooks where context is precious. */
export declare function formatBrief(findings: Finding[], limit?: number): string;
export declare function formatAdvisory(a: Advisory, pkg?: string): string;
/** Vulnerable-package counts per lockfile/manifest, most findings first. */
export declare function countByFile(findings: Finding[]): {
    file: string;
    vulnerable: number;
    worst: Severity;
    counts: string;
}[];
/** Machine-readable form for MCP structuredContent. Advisories are capped so big scans stay small. */
export declare function findingJson(f: Finding, maxAdvisories?: number): {
    ecosystem: import("./types.js").Ecosystem;
    name: string;
    version: string;
    direct: boolean;
    dev: boolean;
    via: string[] | undefined;
    source: string;
    severity: Severity;
    safeVersion: string | null;
    noFix: boolean;
    fix: string | null;
    advisoryCount: number;
    advisories: {
        id: string;
        cve: string | null;
        severity: Severity;
        score: number | null;
        summary: string;
        affected: string[];
    }[];
};
