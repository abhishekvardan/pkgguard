import type { Manager } from './detect.js';
/** A command to run: argv, no shell parsing on POSIX. */
export interface Cmd {
    cmd: string;
    args: string[];
}
export declare function showCmd(c: Cmd): string;
export declare function runCmd(c: Cmd, cwd: string): number;
export interface AddItem {
    name: string;
    /** Version or range to request; undefined = latest. */
    version?: string;
    /** The spec exactly as the user typed it, used when nothing needs changing. */
    original: string;
    /** True when pkgguard replaced the requested version with a safe one. */
    changed: boolean;
}
/** The spec token(s) for one package in the manager's own syntax. */
export declare function specFor(m: Manager, it: AddItem): string;
/** The install command(s) for these packages. bundle and dotnet take one package per command. */
export declare function addCommands(m: Manager, items: AddItem[], dev: boolean, extra?: string[]): Cmd[];
/** Install exactly what the manifest/lockfile says (`ci` = frozen lockfile, for CI). */
export declare function syncCommand(m: Manager, root: string, ci?: boolean, extra?: string[]): Cmd | undefined;
