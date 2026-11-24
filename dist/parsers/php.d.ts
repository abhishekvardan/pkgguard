import type { Dep } from '../types.js';
/** composer.lock (+ composer.json beside it for direct dependencies). */
export declare function parseComposerLock(text: string, source: string, composerJson?: string): Dep[];
