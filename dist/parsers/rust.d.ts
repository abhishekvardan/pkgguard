import type { Dep } from '../types.js';
/**
 * Cargo.lock. Packages without a registry `source` are the workspace's own crates;
 * their dependencies are the direct ones.
 */
export declare function parseCargoLock(text: string, source: string): Dep[];
