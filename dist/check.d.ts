import type { Ecosystem, Tool } from './types.js';
import { type NetOpts } from './core/osv.js';
export declare function parseEcosystem(s: string): Ecosystem | undefined;
export declare const DEFAULT_TOOL: Record<Ecosystem, Tool>;
export interface CheckResult {
    text: string;
    json: any;
}
/** Is name@version vulnerable? Without a version: its history and whether the latest release is clean. */
export declare function checkPackage(ecosystem: Ecosystem, name: string, version: string | undefined, opts?: NetOpts): Promise<CheckResult>;
export declare function getVulnerability(id: string, opts?: NetOpts): Promise<CheckResult | undefined>;
