import type { Dep, Ecosystem, Tool } from '../types.js';
export interface ParsedManifest {
    path: string;
    ecosystem: Ecosystem;
    tool: Tool;
    deps: Dep[];
    unpinned: number;
}
/** True for any file name pkgguard knows how to read. */
export declare function isDependencyFile(name: string): boolean;
/** Parse one dependency file. `root` is used for the relative `source` path. */
export declare function parseFile(file: string, root: string): ParsedManifest | undefined;
/** Every dependency file under `root`, skipping vendored / generated folders. */
export declare function findDependencyFiles(root: string): string[];
export declare function parseProject(root: string): {
    manifests: ParsedManifest[];
    errors: string[];
};
