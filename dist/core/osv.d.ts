import type { Advisory, Ecosystem, Range } from '../types.js';
export interface NetOpts {
    timeoutMs?: number;
    retries?: number;
}
export interface PkgQuery {
    ecosystem: Ecosystem;
    name: string;
    version?: string;
}
/** PEP 503 for PyPI; everything else is case-sensitive as written. */
export declare function normalizeName(ecosystem: Ecosystem, name: string): string;
/** Version string as OSV expects it for the ecosystem. */
export declare function osvVersion(ecosystem: Ecosystem, version: string): string;
/** Vulnerability IDs affecting each query, in the same order. */
export declare function queryIds(queries: PkgQuery[], opts?: NetOpts): Promise<string[][]>;
/** Full OSV records, keyed by ID. Unknown IDs are simply absent. */
export declare function getVulns(ids: string[], opts?: NetOpts): Promise<Map<string, any>>;
/** Collapse OSV range events into [introduced, fixed | last_affected) intervals. */
export declare function rangesFromEvents(events: any[]): Range[];
/** The parts of an OSV record that concern one package. */
export declare function toAdvisory(vuln: any, ecosystem: Ecosystem, name: string): Advisory;
/** Advisories (withdrawn ones removed) for each query, in the same order. */
export declare function advisoriesFor(queries: PkgQuery[], opts?: NetOpts): Promise<Advisory[][]>;
