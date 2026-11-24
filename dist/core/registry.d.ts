import type { Ecosystem } from '../types.js';
import { type FetchOpts } from './http.js';
export declare function latestVersion(ecosystem: Ecosystem, name: string, opts?: FetchOpts): Promise<string | undefined>;
/** What `npm install name@range` would resolve to (npm-style ranges only). */
export declare function npmResolve(name: string, range: string, opts?: FetchOpts): Promise<string | undefined>;
