import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { Ecosystem } from '../types.js';

/**
 * Which package manager owns a project: decided by its lockfile first (that is what the
 * team actually runs), then by its manifest. Searches upward like the managers themselves do.
 */

export type Manager =
  | 'npm' | 'pnpm' | 'yarn' | 'bun'
  | 'uv' | 'poetry' | 'pipenv' | 'pip'
  | 'cargo' | 'go' | 'bundle' | 'composer' | 'dotnet';

export const MANAGERS: Manager[] = ['npm', 'pnpm', 'yarn', 'bun', 'uv', 'poetry', 'pipenv', 'pip', 'cargo', 'go', 'bundle', 'composer', 'dotnet'];

export const MANAGER_ECOSYSTEM: Record<Manager, Ecosystem> = {
  npm: 'npm', pnpm: 'npm', yarn: 'npm', bun: 'npm',
  uv: 'PyPI', poetry: 'PyPI', pipenv: 'PyPI', pip: 'PyPI',
  cargo: 'crates.io', go: 'Go', bundle: 'RubyGems', composer: 'Packagist', dotnet: 'NuGet',
};

/** Files a manager reads or writes, backed up by `add --strict`. */
export const MANAGER_FILES: Record<Manager, string[]> = {
  npm: ['package.json', 'package-lock.json', 'npm-shrinkwrap.json'],
  pnpm: ['package.json', 'pnpm-lock.yaml'],
  yarn: ['package.json', 'yarn.lock'],
  bun: ['package.json', 'bun.lock', 'bun.lockb'],
  uv: ['pyproject.toml', 'uv.lock'],
  poetry: ['pyproject.toml', 'poetry.lock'],
  pipenv: ['Pipfile', 'Pipfile.lock'],
  pip: ['requirements.txt'],
  cargo: ['Cargo.toml', 'Cargo.lock'],
  go: ['go.mod', 'go.sum'],
  bundle: ['Gemfile', 'Gemfile.lock'],
  composer: ['composer.json', 'composer.lock'],
  dotnet: ['packages.lock.json'],
};

// Lockfiles win over manifests; within a tier, the first match wins.
const LOCKS: [string, Manager][] = [
  ['pnpm-lock.yaml', 'pnpm'], ['yarn.lock', 'yarn'], ['bun.lock', 'bun'], ['bun.lockb', 'bun'],
  ['package-lock.json', 'npm'], ['npm-shrinkwrap.json', 'npm'],
  ['uv.lock', 'uv'], ['poetry.lock', 'poetry'], ['Pipfile.lock', 'pipenv'],
  ['Cargo.lock', 'cargo'], ['go.sum', 'go'], ['Gemfile.lock', 'bundle'], ['composer.lock', 'composer'], ['packages.lock.json', 'dotnet'],
];

function fromManifest(dir: string, files: Set<string>): Manager | undefined {
  if (files.has('package.json')) {
    // "packageManager": "pnpm@9.1.0" (corepack) names the tool outright.
    try {
      const pm = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))?.packageManager;
      const name = typeof pm === 'string' ? pm.split('@')[0] : undefined;
      if (name && ['npm', 'pnpm', 'yarn', 'bun'].includes(name)) return name as Manager;
    } catch {
      // unreadable package.json: fall through to npm
    }
    return 'npm';
  }
  if (files.has('pyproject.toml')) {
    const text = (() => {
      try {
        return readFileSync(join(dir, 'pyproject.toml'), 'utf8');
      } catch {
        return '';
      }
    })();
    if (/^\[tool\.poetry\]/m.test(text)) return 'poetry';
    if (/^\[tool\.uv\]/m.test(text) || /^\[project\]/m.test(text)) return 'uv';
    return 'pip';
  }
  if (files.has('Pipfile')) return 'pipenv';
  if ([...files].some((f) => /^requirements.*\.txt$/i.test(f))) return 'pip';
  if (files.has('Cargo.toml')) return 'cargo';
  if (files.has('go.mod')) return 'go';
  if (files.has('Gemfile')) return 'bundle';
  if (files.has('composer.json')) return 'composer';
  if ([...files].some((f) => /\.(cs|fs|vb)proj$/i.test(f))) return 'dotnet';
  return undefined;
}

export function detectIn(dir: string): Manager | undefined {
  let files: Set<string>;
  try {
    files = new Set(readdirSync(dir));
  } catch {
    return undefined;
  }
  for (const [f, m] of LOCKS) if (files.has(f)) return m;
  return fromManifest(dir, files);
}

/** The nearest directory at or above `start` with a recognisable project, and its manager. */
export function detectManager(start: string, prefer?: string): { manager: Manager; root: string } | undefined {
  if (prefer) {
    const p = prefer.toLowerCase() === 'bundler' ? 'bundle' : (prefer.toLowerCase() as Manager);
    if (!MANAGERS.includes(p)) throw new Error(`Unknown package manager "${prefer}". Use one of: ${MANAGERS.join(', ')}.`);
    return { manager: p, root: resolve(start) };
  }
  let dir = resolve(start);
  for (let i = 0; i < 30; i++) {
    const m = detectIn(dir);
    if (m) return { manager: m, root: dir };
    if (existsSync(join(dir, '.git'))) return undefined;
    const up = dirname(dir);
    if (up === dir) return undefined;
    dir = up;
  }
  return undefined;
}
