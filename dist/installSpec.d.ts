import type { Ecosystem } from './types.js';
/**
 * Recognise package installs inside a shell command, e.g.
 *   npm i lodash@4.17.15 && pip install "requests==2.19.0"
 * so the PreToolUse hook can check them before they run.
 */
export interface InstallIntent {
    ecosystem: Ecosystem;
    name: string;
    /** exact: `version` is what gets installed; latest: newest release; range: npm range / dist-tag in `version`. */
    kind: 'exact' | 'latest' | 'range';
    version?: string;
    /** The token as written. */
    spec: string;
    manager: string;
}
export interface ParsedCommand {
    intents: InstallIntent[];
    /** `pip install -r <file>` files to scan. */
    requirementFiles: string[];
}
/** Split into simple commands on && || ; | and newlines, respecting quotes. */
export declare function splitCommands(cmd: string): string[];
export declare function tokenize(cmd: string): string[];
export declare function parseInstallCommand(command: string): ParsedCommand;
