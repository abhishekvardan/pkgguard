import type { Dep } from '../types.js';
/** Requirement name from a PEP 508 string: "requests[security]>=2; python_version<'3'" -> "requests". */
export declare function reqName(spec: string): string | undefined;
/**
 * requirements*.txt. Only `==` / `===` pins are checked. pip-compile "# via" annotations
 * are used to tell direct from transitive dependencies.
 */
export declare function parseRequirements(text: string, source: string): {
    deps: Dep[];
    unpinned: number;
};
/** Names declared in pyproject.toml: [project] dependencies, poetry tables, dependency groups. */
export declare function readPyproject(text: string | undefined): {
    deps: Set<string>;
    dev: Set<string>;
};
/** poetry.lock (any version). */
export declare function parsePoetryLock(text: string, source: string, pyproject?: string): Dep[];
/** uv.lock. The project itself (editable / virtual source) supplies the direct dependencies. */
export declare function parseUvLock(text: string, source: string, pyproject?: string): Dep[];
/** Pipfile.lock (JSON). "develop" packages are dev. */
export declare function parsePipfileLock(text: string, source: string, pipfile?: string): Dep[];
