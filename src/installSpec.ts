import type { Ecosystem } from './types.js';
import { isExactVersion } from './core/version.js';

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
export function splitCommands(cmd: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q: string | undefined;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    if (q) {
      cur += c;
      if (c === q) q = undefined;
      continue;
    }
    if (c === '"' || c === "'") {
      q = c;
      cur += c;
    } else if (c === '\n' || c === ';' || c === '|' || (c === '&' && cmd[i + 1] === '&')) {
      if (c === '&' || (c === '|' && cmd[i + 1] === '|')) i++;
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out.map((s) => s.trim()).filter(Boolean);
}

export function tokenize(cmd: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q: string | undefined;
  let has = false;
  for (const c of cmd) {
    if (q) {
      if (c === q) q = undefined;
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") {
      q = c;
      has = true;
    } else if (/\s/.test(c)) {
      if (cur || has) out.push(cur);
      cur = '';
      has = false;
    } else cur += c;
  }
  if (cur || has) out.push(cur);
  return out;
}

/** Positional args after `start`, skipping flags (and the values of flags in `valueFlags`). */
function positionals(tokens: string[], start: number, valueFlags: string[]): { args: string[]; flags: Map<string, string> } {
  const args: string[] = [];
  const flags = new Map<string, string>();
  for (let i = start; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.startsWith('-')) {
      const [f, inline] = t.split(/=(.*)/s);
      if (inline !== undefined) flags.set(f!, inline);
      else if (valueFlags.includes(t)) flags.set(t, tokens[++i] ?? '');
      else flags.set(t, '');
      continue;
    }
    args.push(t);
  }
  return { args, flags };
}

const LOCAL = /^(\.|\/|~|[A-Za-z]:\\|file:|git\+|git:|https?:|github:|link:|workspace:|portal:)/;

function npmSpec(spec: string, manager: string): InstallIntent | undefined {
  if (LOCAL.test(spec) || spec.endsWith('.tgz')) return undefined;
  const at = spec.startsWith('@') ? spec.indexOf('@', 1) : spec.indexOf('@');
  const name = at > 0 ? spec.slice(0, at) : spec;
  const ver = at > 0 ? spec.slice(at + 1) : '';
  if (!/^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i.test(name)) return undefined; // user/repo shorthand etc.
  if (/^(npm|file|git|github|http|https|link|workspace|patch):/.test(ver)) return undefined;
  if (!ver || ver === 'latest') return { ecosystem: 'npm', name, kind: 'latest', spec, manager };
  if (isExactVersion(ver.replace(/^=/, ''))) return { ecosystem: 'npm', name, kind: 'exact', version: ver.replace(/^=v?/, ''), spec, manager };
  return { ecosystem: 'npm', name, kind: 'range', version: ver, spec, manager };
}

function pySpec(spec: string, manager: string): InstallIntent | undefined {
  const s = spec.split(';')[0]!.trim();
  if (LOCAL.test(s) || /\.(whl|zip|tar\.gz)$/i.test(s) || s.includes('/')) return undefined;
  // poetry style name@version
  let m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?@(.+)$/);
  if (m) {
    const v = m[2]!.trim();
    if (v === 'latest') return { ecosystem: 'PyPI', name: m[1]!, kind: 'latest', spec, manager };
    if (isExactVersion(v.replace(/^==?/, ''))) return { ecosystem: 'PyPI', name: m[1]!, kind: 'exact', version: v.replace(/^==?/, ''), spec, manager };
    return undefined;
  }
  m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(===?|>=|>)\s*([^\s,]+))?\s*$/);
  if (!m) return undefined; // ~=, <, combined specifiers: not checked
  if (!m[2]) return { ecosystem: 'PyPI', name: m[1]!, kind: 'latest', spec, manager };
  if (m[2].startsWith('==')) return { ecosystem: 'PyPI', name: m[1]!, kind: 'exact', version: m[3]!, spec, manager };
  return { ecosystem: 'PyPI', name: m[1]!, kind: 'latest', spec, manager }; // >= / > resolve to the newest release
}

const PIP_VALUE_FLAGS = ['-r', '--requirement', '-c', '--constraint', '-i', '--index-url', '--extra-index-url', '-e', '--editable', '-t', '--target', '--python', '-p', '--prefix', '--root', '-f', '--find-links', '--platform', '--python-version', '--group', '-G', '--source', '--optional', '--extra', '--package', '--directory', '--project'];

function parseOne(tokens: string[], out: ParsedCommand): void {
  // strip env assignments and wrappers
  while (tokens.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0]!) || ['sudo', 'time', 'exec', 'command', 'env', 'nohup'].includes(tokens[0]!))) tokens.shift();
  if (!tokens.length) return;
  const bin = tokens[0]!.replace(/\\/g, '/').split('/').pop()!.replace(/\.(exe|cmd|bat)$/i, '').toLowerCase();
  const sub = tokens[1]?.toLowerCase();
  const push = (i: InstallIntent | undefined) => i && out.intents.push(i);

  // ---- npm family
  const npmValue = ['--registry', '--prefix', '-w', '--workspace', '--filter', '--tag', '--cache', '--userconfig', '-C', '--dir', '--cwd'];
  if ((bin === 'npm' && ['install', 'i', 'in', 'add', 'isntall', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal'].includes(sub ?? '')) ||
      (bin === 'pnpm' && ['add', 'install', 'i'].includes(sub ?? '')) ||
      (bin === 'yarn' && ['add'].includes(sub ?? '')) ||
      (bin === 'bun' && ['add', 'a', 'install', 'i'].includes(sub ?? ''))) {
    // npm's -w takes a workspace name; pnpm's -w is the boolean --workspace-root.
    const { args } = positionals(tokens, 2, bin === 'npm' ? npmValue : npmValue.filter((f) => f !== '-w'));
    for (const a of args) push(npmSpec(a, bin));
    return;
  }

  // ---- Python
  let pyStart = -1;
  let pyManager = '';
  if (['pip', 'pip3'].includes(bin) || /^pip3\.\d+$/.test(bin)) {
    if (sub === 'install') [pyStart, pyManager] = [2, 'pip'];
  } else if (/^(python|python3|py|python3\.\d+)$/.test(bin) && tokens[1] === '-m' && /^pip3?$/.test(tokens[2] ?? '') && tokens[3] === 'install') {
    [pyStart, pyManager] = [4, 'pip'];
  } else if (bin === 'uv' && sub === 'pip' && tokens[2] === 'install') {
    [pyStart, pyManager] = [3, 'uv'];
  } else if (bin === 'uv' && sub === 'add') {
    [pyStart, pyManager] = [2, 'uv'];
  } else if ((bin === 'poetry' || bin === 'pdm' || bin === 'rye') && sub === 'add') {
    [pyStart, pyManager] = [2, bin];
  } else if ((bin === 'pipenv' && sub === 'install') || (bin === 'pipx' && sub === 'install')) {
    [pyStart, pyManager] = [2, bin];
  }
  if (pyStart >= 0) {
    for (let i = pyStart; i < tokens.length; i++) {
      const t = tokens[i]!;
      if (t === '-r' || t === '--requirement') out.requirementFiles.push(tokens[i + 1] ?? '');
      else if (t.startsWith('--requirement=')) out.requirementFiles.push(t.slice(14));
      else if (/^-r\S/.test(t)) out.requirementFiles.push(t.slice(2));
    }
    const { args } = positionals(tokens, pyStart, PIP_VALUE_FLAGS);
    for (const a of args) push(pySpec(a, pyManager));
    out.requirementFiles = out.requirementFiles.filter(Boolean);
    return;
  }

  // ---- Rust
  if (bin === 'cargo' && (sub === 'add' || sub === 'install')) {
    const { args, flags } = positionals(tokens, 2, ['-F', '--features', '-p', '--package', '--rename', '--path', '--git', '--branch', '--tag', '--rev', '--registry', '--target', '--vers', '--version', '--root', '--index']);
    if (flags.has('--git') || flags.has('--path')) return;
    const vers = flags.get('--vers') ?? flags.get('--version');
    for (const a of args) {
      const [name, v = vers] = a.split('@');
      if (!name || !/^[A-Za-z0-9_-]+$/.test(name)) continue;
      const ver = v?.replace(/^[=^]/, '');
      if (ver && isExactVersion(ver)) push({ ecosystem: 'crates.io', name, kind: 'exact', version: ver, spec: a, manager: 'cargo' });
      else if (!ver) push({ ecosystem: 'crates.io', name, kind: 'latest', spec: a, manager: 'cargo' });
    }
    return;
  }

  // ---- Go
  if (bin === 'go' && (sub === 'get' || sub === 'install')) {
    const { args } = positionals(tokens, 2, ['-modfile', '-C']);
    for (const a of args) {
      const [mod, v] = a.split('@');
      if (!mod || !mod.includes('.') || mod.startsWith('.')) continue;
      if (!v || v === 'latest' || v === 'upgrade') push({ ecosystem: 'Go', name: mod.replace(/\/\.\.\.$/, ''), kind: 'latest', spec: a, manager: 'go' });
      else if (/^v\d/.test(v) && isExactVersion(v)) push({ ecosystem: 'Go', name: mod.replace(/\/\.\.\.$/, ''), kind: 'exact', version: v.slice(1), spec: a, manager: 'go' });
    }
    return;
  }

  // ---- Ruby
  if ((bin === 'gem' && sub === 'install') || (bin === 'bundle' && sub === 'add')) {
    const { args, flags } = positionals(tokens, 2, ['-v', '--version', '--source', '--group', '-g', '--require', '--install-dir', '-i']);
    const ver = flags.get('-v') ?? flags.get('--version');
    for (const a of args) {
      const [name, inline] = a.split(':');
      if (!name || !/^[A-Za-z0-9_.-]+$/.test(name)) continue;
      const v = (inline ?? ver)?.trim();
      if (v && isExactVersion(v)) push({ ecosystem: 'RubyGems', name, kind: 'exact', version: v, spec: a, manager: bin });
      else if (!v) push({ ecosystem: 'RubyGems', name, kind: 'latest', spec: a, manager: bin });
    }
    return;
  }

  // ---- PHP
  if (bin === 'composer' && (sub === 'require' || sub === 'req')) {
    const { args } = positionals(tokens, 2, ['--working-dir', '-d']);
    for (let i = 0; i < args.length; i++) {
      const a = args[i]!;
      const m = a.match(/^([a-z0-9_.-]+\/[a-z0-9_.-]+)(?:[:=\s](.+))?$/i);
      if (!m) continue;
      let v = m[2]?.trim();
      // "vendor/pkg 1.2.3" as two tokens
      if (!v && args[i + 1] && !args[i + 1]!.includes('/')) v = args[++i];
      v = v?.replace(/^v(?=\d)/, '');
      if (v && isExactVersion(v)) push({ ecosystem: 'Packagist', name: m[1]!, kind: 'exact', version: v, spec: a, manager: 'composer' });
      else if (!v || v === '*') push({ ecosystem: 'Packagist', name: m[1]!, kind: 'latest', spec: a, manager: 'composer' });
    }
    return;
  }

  // ---- .NET
  if (bin === 'dotnet' && tokens.includes('package') && tokens.includes('add')) {
    const at = tokens.indexOf('package');
    const { args, flags } = positionals(tokens, at + 1, ['-v', '--version', '-f', '--framework', '-s', '--source', '--package-directory']);
    const name = args[0];
    if (!name) return;
    const v = flags.get('-v') ?? flags.get('--version');
    if (v && isExactVersion(v)) push({ ecosystem: 'NuGet', name, kind: 'exact', version: v, spec: name, manager: 'dotnet' });
    else if (!v) push({ ecosystem: 'NuGet', name, kind: 'latest', spec: name, manager: 'dotnet' });
  }
}

export function parseInstallCommand(command: string): ParsedCommand {
  const out: ParsedCommand = { intents: [], requirementFiles: [] };
  for (const part of splitCommands(command)) {
    try {
      parseOne(tokenize(part), out);
    } catch {
      // never let a weird command break the hook
    }
  }
  return out;
}
