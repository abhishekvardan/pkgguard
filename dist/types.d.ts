/** Ecosystem names exactly as OSV.dev spells them. */
export type Ecosystem = 'npm' | 'PyPI' | 'Go' | 'crates.io' | 'Maven' | 'RubyGems' | 'Packagist' | 'NuGet';
export declare const ECOSYSTEMS: Ecosystem[];
/** The tool that owns a manifest — decides which fix command to suggest. */
export type Tool = 'npm' | 'pnpm' | 'yarn' | 'pip' | 'poetry' | 'uv' | 'pipenv' | 'go' | 'cargo' | 'bundler' | 'composer' | 'nuget' | 'maven' | 'gradle';
export interface Dep {
    ecosystem: Ecosystem;
    name: string;
    version: string;
    /** Listed directly in the project's manifest (as opposed to pulled in by another package). */
    direct: boolean;
    /** Only used for development / tests. */
    dev: boolean;
    /** Manifest or lockfile it was read from, relative to the scanned root. */
    source: string;
    tool: Tool;
    /** For transitive deps: the chain from a direct dependency down to this one (excluding itself). */
    via?: string[];
}
export type Severity = 'unknown' | 'low' | 'moderate' | 'high' | 'critical';
export declare const SEVERITY_RANK: Record<Severity, number>;
export interface Range {
    introduced?: string;
    fixed?: string;
    lastAffected?: string;
}
export interface Advisory {
    id: string;
    aliases: string[];
    summary: string;
    severity: Severity;
    score?: number;
    /** Affected ranges for this specific package. */
    ranges: Range[];
    /** Explicitly listed affected versions, when OSV gives them. */
    versions: string[];
    published?: string;
    references: string[];
}
export interface Finding {
    dep: Dep;
    advisories: Advisory[];
    severity: Severity;
    /** Lowest version that clears every advisory, when one exists and was verified. */
    safeVersion?: string;
    /** True when at least one advisory has no fixed version at all. */
    noFix: boolean;
}
export interface ScanResult {
    root: string;
    manifests: {
        path: string;
        ecosystem: Ecosystem;
        tool: Tool;
        deps: number;
    }[];
    dependencies: number;
    findings: Finding[];
    notes: string[];
}
