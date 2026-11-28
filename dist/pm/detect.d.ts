import type { Ecosystem } from '../types.js';
/**
 * Which package manager owns a project: decided by its lockfile first (that is what the
 * team actually runs), then by its manifest. Searches upward like the managers themselves do.
 */
export type Manager = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'uv' | 'poetry' | 'pipenv' | 'pip' | 'cargo' | 'go' | 'bundle' | 'composer' | 'dotnet';
export declare const MANAGERS: Manager[];
export declare const MANAGER_ECOSYSTEM: Record<Manager, Ecosystem>;
/** Files a manager reads or writes, backed up by `add --strict`. */
export declare const MANAGER_FILES: Record<Manager, string[]>;
export declare function detectIn(dir: string): Manager | undefined;
/** The nearest directory at or above `start` with a recognisable project, and its manager. */
export declare function detectManager(start: string, prefer?: string): {
    manager: Manager;
    root: string;
} | undefined;
