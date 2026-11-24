import type { Range } from '../types.js';
export declare function compareVersions(a: string, b: string): number;
export declare function isPrerelease(v: string): boolean;
export declare function major(v: string): number | undefined;
export declare function inRange(v: string, r: Range): boolean;
/** True for a plain, fully specified version such as 1.2.3, 2.0.0-rc.1 or v0.3.7. */
export declare function isExactVersion(spec: string): boolean;
/**
 * Highest version in `versions` satisfying an npm-style range. Supports the forms people
 * actually type: 1.2.3, ^1.2.3, ~1.2.3, 1, 1.2, 1.x, 1.2.x, *, >=1.2.3. Returns undefined
 * for anything more exotic so the caller can say it did not check.
 */
export declare function maxSatisfying(versions: string[], range: string): string | undefined;
