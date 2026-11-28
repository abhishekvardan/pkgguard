import type { Dep, Tool } from './types.js';
import type { NetOpts } from './core/osv.js';
import type { InstallIntent } from './installSpec.js';
/** Which fix-command style a package manager binary uses. */
export declare const MANAGER_TOOL: Record<string, Tool>;
/** The exact version an install intent would get, or undefined when it can't be told (offline, non-npm range). */
export declare function resolveIntent(i: InstallIntent, net?: NetOpts): Promise<string | undefined>;
/** A Dep for what an install intent resolves to, ready for checkDeps. */
export declare function intentDep(i: InstallIntent, version: string, dev?: boolean): Dep;
