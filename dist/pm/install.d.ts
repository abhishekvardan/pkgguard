import type { Severity } from '../types.js';
/**
 * `pkgguard install [--ci]`: install what the lockfile says, but check it first. When the
 * lockfile already pins something at or above `failOn` (default high), refuse before any
 * package is downloaded, unless --allow-vulnerable. Without a lockfile, install first and
 * check what was resolved.
 */
export interface InstallOpts {
    cwd: string;
    pm?: string;
    ci?: boolean;
    allowVulnerable?: boolean;
    failOn?: Severity;
    extra?: string[];
    log?: (s: string) => void;
}
export declare function runInstall(opts: InstallOpts): Promise<number>;
