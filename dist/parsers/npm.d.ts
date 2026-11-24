import type { Dep } from '../types.js';
interface Manifest {
    deps: Set<string>;
    dev: Set<string>;
}
/** Direct and dev dependency names from a package.json (empty if absent / unreadable). */
export declare function readPackageJson(text: string | undefined): Manifest & {
    raw: any;
};
/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3. */
export declare function parsePackageLock(text: string, source: string, pkgJson?: string): Dep[];
/** pnpm-lock.yaml, lockfile versions 5.x, 6.x and 9.x. */
export declare function parsePnpmLock(text: string, source: string, pkgJson?: string): Dep[];
/** yarn.lock — classic (v1) and berry (v2+). */
export declare function parseYarnLock(text: string, source: string, pkgJson?: string): Dep[];
/** package.json with no lockfile next to it: only exact pins can be checked. */
export declare function parsePackageJsonOnly(text: string, source: string): {
    deps: Dep[];
    unpinned: number;
};
export {};
