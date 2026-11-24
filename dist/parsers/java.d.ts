import type { Dep } from '../types.js';
/** gradle.lockfile: `group:artifact:version=configuration,...` per line. */
export declare function parseGradleLock(text: string, source: string): Dep[];
/**
 * pom.xml — direct <dependency> entries with a literal or ${property} version.
 * Transitive dependencies need a Maven resolve and are not read.
 */
export declare function parsePom(text: string, source: string): {
    deps: Dep[];
    unpinned: number;
};
