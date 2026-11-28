import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stateDir } from './state.js';

/**
 * `pkgguard schedule install|status|remove`: run `pkgguard watch <dirs> --notify` on a timer.
 * Windows: a Task Scheduler task for the current user, started through a tiny .vbs so no
 * console window flashes up. macOS/Linux: print the crontab line to add.
 */

export const TASK_NAME = 'pkgguard watch';

export interface Interval {
  unit: 'minute' | 'hour' | 'day';
  n: number;
}

/** "30m", "6h", "1d" (also "90min", "12 hours"). */
export function parseInterval(s: string): Interval {
  const m = s.trim().toLowerCase().match(/^(\d+)\s*(m|min|mins|minutes?|h|hr|hrs|hours?|d|days?)$/);
  if (!m) throw new Error(`Can't read the interval "${s}". Use e.g. 30m, 6h or 1d.`);
  const n = Number(m[1]);
  const unit = m[2]!.startsWith('m') ? 'minute' : m[2]!.startsWith('h') ? 'hour' : 'day';
  const max = { minute: 1439, hour: 23, day: 365 }[unit];
  if (n < 1 || n > max) throw new Error(`${s}: use 1–${max} ${unit}s${unit === 'hour' ? ' (or days, e.g. 1d)' : ''}.`);
  if (unit === 'minute' && n < 15) throw new Error('Watching more often than every 15 minutes only hammers OSV.dev; advisories are not published that fast.');
  return { unit, n };
}

/** schtasks /Create arguments. */
export function schtasksArgs(i: Interval, launcher: string): string[] {
  const sc = { minute: 'MINUTE', hour: 'HOURLY', day: 'DAILY' }[i.unit];
  return ['/Create', '/TN', TASK_NAME, '/SC', sc, '/MO', String(i.n), '/TR', `wscript.exe //B //Nologo "${launcher}"`, '/F'];
}

export function cronLine(i: Interval, command: string): string {
  const spec = i.unit === 'minute' ? `*/${i.n} * * * *` : i.unit === 'hour' ? `0 */${i.n} * * *` : `0 9 */${i.n} * *`;
  return `${spec} ${command}`;
}

const q = (s: string) => `"${s}"`;

/** The watch command line: this node, this cli.js, absolute dirs. */
export function watchCommand(dirs: string[], extra: string[] = []): { exe: string; args: string[] } {
  const cli = fileURLToPath(new URL('../cli.js', import.meta.url));
  return { exe: process.execPath, args: [cli, 'watch', ...dirs.map((d) => resolve(d)), '--notify', ...extra] };
}

export function installSchedule(dirs: string[], every: string, extra: string[] = []): string {
  if (!dirs.length) throw new Error('Name the folder(s) to watch, e.g. pkgguard schedule install --every 6h "M:\\All Projects".');
  const interval = parseInterval(every);
  const { exe, args } = watchCommand(dirs, extra);
  const dir = stateDir();
  mkdirSync(dir, { recursive: true });
  const logFile = join(dir, 'watch.log');

  if (process.platform !== 'win32') {
    const cmd = [exe, ...args].map((a) => `'${a.replace(/'/g, `'\\''`)}'`).join(' ');
    return [
      'Add this line with `crontab -e`:',
      '',
      cronLine(interval, `${cmd} >> '${logFile}' 2>&1`),
      '',
      'Notifications from cron need a desktop session; on macOS they appear under "Script Editor" or "osascript".',
    ].join('\n');
  }

  // A .cmd that runs the watch and appends to the log, and a .vbs that starts it hidden.
  const cmdFile = join(dir, 'watch.cmd');
  const vbsFile = join(dir, 'watch.vbs');
  writeFileSync(cmdFile, `@echo off\r\n${[exe, ...args].map(q).join(' ')} >> ${q(logFile)} 2>&1\r\n`);
  writeFileSync(vbsFile, `CreateObject("WScript.Shell").Run """${cmdFile}""", 0, True\r\n`);
  const r = spawnSync('schtasks', schtasksArgs(interval, vbsFile), { encoding: 'utf8', windowsHide: true });
  if (r.status !== 0) throw new Error(`schtasks failed: ${(r.stderr || r.stdout || '').trim()}`);
  return [
    `Scheduled "${TASK_NAME}" every ${interval.n} ${interval.unit}${interval.n === 1 ? '' : 's'} for: ${dirs.map((d) => resolve(d)).join(', ')}`,
    `It runs while you are signed in, shows a notification when something new is found, and logs to ${logFile}.`,
    'Run it now: pkgguard schedule run · check: pkgguard schedule status · stop: pkgguard schedule remove',
    'After updating pkgguard, run schedule install again so the task uses the new version.',
  ].join('\n');
}

export function scheduleStatus(): string {
  if (process.platform !== 'win32') return 'On macOS/Linux the schedule is a crontab line: see `crontab -l`.';
  const r = spawnSync('schtasks', ['/Query', '/TN', TASK_NAME, '/V', '/FO', 'LIST'], { encoding: 'utf8', windowsHide: true });
  if (r.status !== 0) return `No "${TASK_NAME}" task is scheduled. Create one with: pkgguard schedule install --every 6h <folders>`;
  const keep = /^(TaskName|Next Run Time|Last Run Time|Last Result|Status|Schedule Type|Repeat: Every|Task To Run):/;
  return r.stdout.split(/\r?\n/).filter((l) => keep.test(l)).join('\n') + `\nLog: ${join(stateDir(), 'watch.log')}`;
}

export function runScheduleNow(): string {
  if (process.platform !== 'win32') throw new Error('Run the watch command from your crontab line directly.');
  const r = spawnSync('schtasks', ['/Run', '/TN', TASK_NAME], { encoding: 'utf8', windowsHide: true });
  if (r.status !== 0) throw new Error(`schtasks failed: ${(r.stderr || r.stdout || '').trim()}`);
  return `Started "${TASK_NAME}". Output goes to ${join(stateDir(), 'watch.log')}.`;
}

export function removeSchedule(): string {
  if (process.platform !== 'win32') return 'Remove the pkgguard line with `crontab -e`.';
  const r = spawnSync('schtasks', ['/Delete', '/TN', TASK_NAME, '/F'], { encoding: 'utf8', windowsHide: true });
  if (r.status !== 0) return `No "${TASK_NAME}" task to remove.`;
  return `Removed the "${TASK_NAME}" task.`;
}
