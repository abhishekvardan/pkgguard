import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { existingDir, pathVariants, projectDir } from '../src/core/paths.js';

describe('project paths', () => {
  const root = mkdtempSync(join(tmpdir(), 'pkgguard-'));
  const spaced = join(root, 'All Projects', 'Help');
  mkdirSync(spaced, { recursive: true });
  const escaped = spaced.replace(/ /g, '\ ');

  it('undoes shell escapes and quotes', () => {
    expect(pathVariants('m:\All\ Projects\Help')).toContain('m:\All Projects\Help');
    expect(pathVariants('"/a b/c"')).toContain('/a b/c');
  });

  it('finds the real directory behind an escaped path', () => {
    expect(existingDir(escaped)).toBe(spaced);
    expect(existingDir(`"${spaced}"`)).toBe(spaced);
    expect(existingDir(spaced)).toBe(spaced);
    expect(existingDir(join(root, 'missing'))).toBeUndefined();
  });

  it('prefers the unescaped directory when the escaped spelling also exists', () => {
    mkdirSync(escaped, { recursive: true }); // what a tool that mis-escaped the path leaves behind
    expect(existingDir(escaped)).toBe(spaced);
  });

  it('projectDir skips candidates that are not directories', () => {
    expect(projectDir(undefined, join(root, 'nope'), escaped)).toBe(spaced);
    expect(projectDir(undefined)).toBe(process.cwd());
  });
});
