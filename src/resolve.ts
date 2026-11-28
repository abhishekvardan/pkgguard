import type { Dep, Tool } from './types.js';
import type { NetOpts } from './core/osv.js';
import { latestVersion, npmResolve } from './core/registry.js';
import type { InstallIntent } from './installSpec.js';

/** Which fix-command style a package manager binary uses. */
export const MANAGER_TOOL: Record<string, Tool> = {
  npm: 'npm', pnpm: 'pnpm', yarn: 'yarn', bun: 'npm',
  pip: 'pip', uv: 'uv', poetry: 'poetry', pdm: 'pip', rye: 'pip', pipenv: 'pipenv', pipx: 'pip',
  cargo: 'cargo', go: 'go', gem: 'bundler', bundle: 'bundler', composer: 'composer', dotnet: 'nuget',
};

/** The exact version an install intent would get, or undefined when it can't be told (offline, non-npm range). */
export async function resolveIntent(i: InstallIntent, net: NetOpts = {}): Promise<string | undefined> {
  if (i.kind === 'exact') return i.version;
  if (i.kind === 'latest') return latestVersion(i.ecosystem, i.name, net);
  if (i.ecosystem === 'npm' && i.version) return npmResolve(i.name, i.version, net);
  return undefined;
}

/** A Dep for what an install intent resolves to, ready for checkDeps. */
export function intentDep(i: InstallIntent, version: string, dev = false): Dep {
  return {
    ecosystem: i.ecosystem,
    name: i.name,
    version,
    direct: true,
    dev,
    source: i.kind === 'exact' ? 'command' : `command (${i.spec} resolves to ${version})`,
    tool: MANAGER_TOOL[i.manager] ?? 'npm',
  };
}
