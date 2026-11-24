/**
 * Spellings of a directory path to try, unescaped first. Claude Code can hand over a
 * shell-escaped path such as `m:\All\ Projects\Help` (via CLAUDE_PROJECT_DIR or a tool
 * argument), and users paste paths in quotes. The unescaped spelling wins even when the
 * literal one also exists: tools that mis-escape a path once tend to create it, leaving a
 * near-empty `M:\All\ Projects` (a folder named " Projects") beside the real project.
 * On Windows only `\ ` is undone, because `\(` there is an ordinary separator.
 */
export declare function pathVariants(p: string): string[];
/** The first spelling of `p` that is an existing directory, or undefined. */
export declare function existingDir(p: string | undefined): string | undefined;
/** The project root: the first of the candidates that is a real directory (after unescaping), else the cwd. */
export declare function projectDir(...candidates: (string | undefined)[]): string;
