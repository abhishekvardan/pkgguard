import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Manager } from './detect.js';

/** A command to run: argv, no shell parsing on POSIX. */
export interface Cmd {
  cmd: string;
  args: string[];
}

const PY = process.platform === 'win32' ? 'python' : 'python3';

/** cmd.exe quoting (Windows runs npm/pnpm/yarn through their .cmd shims, so it needs a shell). */
function winQuote(a: string): string {
  if (a && /^[\w@./:+=,-]+$/.test(a)) return a;
  return `"${a.replace(/"/g, '""')}"`;
}

export function showCmd(c: Cmd): string {
  return [c.cmd, ...c.args].map((a) => (/^[\w@./:+=,^~-]+$/.test(a) ? a : `"${a.replace(/"/g, '\\"')}"`)).join(' ');
}

export function runCmd(c: Cmd, cwd: string): number {
  const win = process.platform === 'win32';
  const r = win
    ? spawnSync([c.cmd, ...c.args].map(winQuote).join(' '), { cwd, stdio: 'inherit', shell: true })
    : spawnSync(c.cmd, c.args, { cwd, stdio: 'inherit' });
  if (r.error) throw new Error(`could not run ${c.cmd}: ${r.error.message}`);
  return r.status ?? 1;
}

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
export function specFor(m: Manager, it: AddItem): string {
  const v = it.version;
  if (!it.changed) {
    if (m === 'go') return v ? `${it.name}@${v.startsWith('v') ? v : `v${v}`}` : `${it.name}@latest`;
    if (m === 'composer') return v ? `${it.name}:${v}` : it.name;
    if (m === 'cargo') return v ? `${it.name}@${v}` : it.name;
    return it.original;
  }
  switch (m) {
    case 'npm':
    case 'pnpm':
    case 'yarn':
    case 'bun':
    case 'cargo':
      return `${it.name}@${v}`; // saved as ^v by default
    case 'pip':
      return `${it.name}==${v}`;
    case 'uv':
    case 'pipenv':
      return `${it.name}>=${v}`;
    case 'poetry':
      return `${it.name}@^${v}`;
    case 'go':
      return `${it.name}@v${v!.replace(/^v/, '')}`;
    case 'composer':
      return `${it.name}:^${v}`;
    case 'bundle':
    case 'dotnet':
      return it.name;
  }
}

/** The install command(s) for these packages. bundle and dotnet take one package per command. */
export function addCommands(m: Manager, items: AddItem[], dev: boolean, extra: string[] = []): Cmd[] {
  const specs = items.map((i) => specFor(m, i));
  switch (m) {
    case 'npm':
      return [{ cmd: 'npm', args: ['install', ...(dev ? ['-D'] : []), ...specs, ...extra] }];
    case 'pnpm':
      return [{ cmd: 'pnpm', args: ['add', ...(dev ? ['-D'] : []), ...specs, ...extra] }];
    case 'yarn':
      return [{ cmd: 'yarn', args: ['add', ...(dev ? ['-D'] : []), ...specs, ...extra] }];
    case 'bun':
      return [{ cmd: 'bun', args: ['add', ...(dev ? ['--dev'] : []), ...specs, ...extra] }];
    case 'pip':
      return [{ cmd: PY, args: ['-m', 'pip', 'install', ...specs, ...extra] }];
    case 'uv':
      return [{ cmd: 'uv', args: ['add', ...(dev ? ['--dev'] : []), ...specs, ...extra] }];
    case 'poetry':
      return [{ cmd: 'poetry', args: ['add', ...(dev ? ['--group', 'dev'] : []), ...specs, ...extra] }];
    case 'pipenv':
      return [{ cmd: 'pipenv', args: ['install', ...(dev ? ['--dev'] : []), ...specs, ...extra] }];
    case 'cargo':
      return [{ cmd: 'cargo', args: ['add', ...(dev ? ['--dev'] : []), ...specs, ...extra] }];
    case 'go':
      return [{ cmd: 'go', args: ['get', ...specs, ...extra] }];
    case 'composer':
      return [{ cmd: 'composer', args: ['require', ...(dev ? ['--dev'] : []), ...specs, ...extra] }];
    case 'bundle':
      return items.map((i) => ({
        cmd: 'bundle',
        args: ['add', i.name, ...(i.version ? ['--version', i.changed ? `~> ${i.version}` : i.version] : []), ...(dev ? ['--group', 'development'] : []), ...extra],
      }));
    case 'dotnet':
      return items.map((i) => ({ cmd: 'dotnet', args: ['add', 'package', i.name, ...(i.version ? ['--version', i.version] : []), ...extra] }));
  }
}

/** Install exactly what the manifest/lockfile says (`ci` = frozen lockfile, for CI). */
export function syncCommand(m: Manager, root: string, ci = false, extra: string[] = []): Cmd | undefined {
  const has = (f: string) => existsSync(join(root, f));
  switch (m) {
    case 'npm':
      return { cmd: 'npm', args: [ci && (has('package-lock.json') || has('npm-shrinkwrap.json')) ? 'ci' : 'install', ...extra] };
    case 'pnpm':
      return { cmd: 'pnpm', args: ['install', ...(ci ? ['--frozen-lockfile'] : []), ...extra] };
    case 'yarn':
      return { cmd: 'yarn', args: ['install', ...(ci ? [has('.yarnrc.yml') ? '--immutable' : '--frozen-lockfile'] : []), ...extra] };
    case 'bun':
      return { cmd: 'bun', args: ['install', ...(ci ? ['--frozen-lockfile'] : []), ...extra] };
    case 'uv':
      return { cmd: 'uv', args: ['sync', ...(ci ? ['--locked'] : []), ...extra] };
    case 'poetry':
      return { cmd: 'poetry', args: ['install', ...extra] };
    case 'pipenv':
      return { cmd: 'pipenv', args: [ci ? 'sync' : 'install', ...extra] };
    case 'pip': {
      const req = has('requirements.txt') ? 'requirements.txt' : readdirSafe(root).find((f) => /^requirements.*\.txt$/i.test(f));
      return req ? { cmd: PY, args: ['-m', 'pip', 'install', '-r', req, ...extra] } : undefined;
    }
    case 'cargo':
      return { cmd: 'cargo', args: ['fetch', ...(ci ? ['--locked'] : []), ...extra] };
    case 'go':
      return { cmd: 'go', args: ['mod', 'download', ...extra] };
    case 'bundle':
      return { cmd: 'bundle', args: ['install', ...extra] };
    case 'composer':
      return { cmd: 'composer', args: ['install', ...extra] };
    case 'dotnet':
      return { cmd: 'dotnet', args: ['restore', ...(ci ? ['--locked-mode'] : []), ...extra] };
  }
}

function readdirSafe(d: string): string[] {
  try {
    return readdirSync(d);
  } catch {
    return [];
  }
}
