import { existsSync, statSync } from 'node:fs';

function isDir(p: string): boolean {
  try {
    return existsSync(p) && statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Spellings of a directory path to try, unescaped first. Claude Code can hand over a
 * shell-escaped path such as `m:\All\ Projects\Help` (via CLAUDE_PROJECT_DIR or a tool
 * argument), and users paste paths in quotes. The unescaped spelling wins even when the
 * literal one also exists: tools that mis-escape a path once tend to create it, leaving a
 * near-empty `M:\All\ Projects` (a folder named " Projects") beside the real project.
 * On Windows only `\ ` is undone, because `\(` there is an ordinary separator.
 */
export function pathVariants(p: string): string[] {
  const t = p.trim();
  const unquoted = t.replace(/^(['"])(.*)\1$/, '$2');
  const escapes = process.platform === 'win32' ? /\\( )/g : /\\([ '"()&;$`!#\[\]{}])/g;
  const unescaped = unquoted.replace(escapes, '$1');
  return [...new Set([unescaped, unquoted, t].filter(Boolean))];
}

/** The first spelling of `p` that is an existing directory, or undefined. */
export function existingDir(p: string | undefined): string | undefined {
  if (!p) return undefined;
  return pathVariants(p).find(isDir);
}

/** The project root: the first of the candidates that is a real directory (after unescaping), else the cwd. */
export function projectDir(...candidates: (string | undefined)[]): string {
  for (const c of candidates) {
    const d = existingDir(c);
    if (d) return d;
  }
  return process.cwd();
}
