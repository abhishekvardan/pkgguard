import type { Dep } from '../types.js';
/**
 * go.mod. Since Go 1.17 it lists every module in the build (indirect ones marked
 * `// indirect`), so go.sum — which also holds versions no longer used — is not read.
 * `replace` directives pointing at another module version are applied; local paths are skipped.
 */
export declare function parseGoMod(text: string, source: string): Dep[];
