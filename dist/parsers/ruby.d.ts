import type { Dep } from '../types.js';
/** Gemfile.lock — the GEM specs section and the DEPENDENCIES section. */
export declare function parseGemfileLock(text: string, source: string): Dep[];
