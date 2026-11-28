import type { Finding, Severity } from '../types.js';
import { type InstallIntent } from '../installSpec.js';
import { type Manager } from './detect.js';
import { type AddItem } from './run.js';
/**
 * `pkgguard add <pkg…>`: a guarded front for the project's own package manager.
 *  1. resolve what each spec would install and check it against OSV.dev;
 *  2. swap a vulnerable version for the nearest safe one (or refuse when none exists);
 *  3. run the real install;
 *  4. re-scan and report vulnerable packages the install pulled in transitively
 *     (`--strict`: put the manifest and lockfile back and fail).
 */
export declare function parseSpec(m: Manager, spec: string): InstallIntent | undefined;
export interface AddOpts {
    cwd: string;
    pm?: string;
    dev?: boolean;
    strict?: boolean;
    allowVulnerable?: boolean;
    dryRun?: boolean;
    min?: Severity;
    /** Extra arguments passed to the package manager as-is (after `--`). */
    extra?: string[];
    log?: (s: string) => void;
}
interface Planned {
    item: AddItem;
    intent?: InstallIntent;
    resolved?: string;
    finding?: Finding;
}
/** Decide what to install: pure given the findings, so it can be tested offline. */
export declare function planItems(specs: {
    original: string;
    intent?: InstallIntent;
    resolved?: string;
}[], findings: Finding[], allowVulnerable?: boolean): {
    planned: Planned[];
    blocked: Planned[];
    notes: string[];
};
export declare function runAdd(specs: string[], opts: AddOpts): Promise<number>;
export {};
