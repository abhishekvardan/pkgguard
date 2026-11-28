import type { Severity } from '../types.js';
import { type Entry } from './state.js';
/**
 * `pkgguard watch <dirs…>`: scan every project under the given folders, compare with the last
 * run, and report what is new — above all, newly published advisories against versions that
 * were already installed, which no install or edit would ever surface.
 */
/** Project roots under `dir`: a folder with `.git`, or with a dependency file, ends the descent. */
export declare function findProjects(dir: string, maxDepth?: number): string[];
export interface WatchOpts {
    /** Severity that counts as "something new" for the exit code and the notification. */
    min?: Severity;
    notify?: boolean;
    json?: boolean;
    log?: (s: string) => void;
}
export interface ProjectReport {
    root: string;
    firstRun: boolean;
    added: Entry[];
    resolved: Entry[];
    total: number;
    error?: string;
}
export declare function runWatch(dirs: string[], opts?: WatchOpts): Promise<{
    reports: ProjectReport[];
    alert: Entry[];
}>;
