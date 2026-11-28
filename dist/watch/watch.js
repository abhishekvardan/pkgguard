import { existsSync, readdirSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { atLeast } from '../core/severity.js';
import { isDependencyFile, SKIP_DIRS } from '../parsers/detect.js';
import { loadPolicy } from '../policy.js';
import { scanProject } from '../scan.js';
import { formatEntries, groupEntries, loadState, recordScan, saveState } from './state.js';
import { notify } from './notify.js';
/**
 * `pkgguard watch <dirs…>`: scan every project under the given folders, compare with the last
 * run, and report what is new — above all, newly published advisories against versions that
 * were already installed, which no install or edit would ever surface.
 */
/** Project roots under `dir`: a folder with `.git`, or with a dependency file, ends the descent. */
export function findProjects(dir, maxDepth = 3) {
    const out = [];
    const walk = (d, depth) => {
        let entries;
        try {
            entries = readdirSync(d, { withFileTypes: true });
        }
        catch {
            return;
        }
        if (existsSync(join(d, '.git')) || entries.some((e) => e.isFile() && isDependencyFile(e.name))) {
            out.push(d);
            return;
        }
        if (depth >= maxDepth)
            return;
        for (const e of entries) {
            if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.'))
                walk(join(d, e.name), depth + 1);
        }
    };
    walk(resolve(dir), 0);
    return out;
}
export async function runWatch(dirs, opts = {}) {
    const log = opts.log ?? ((s) => console.log(s));
    const roots = [...new Set(dirs.flatMap((d) => findProjects(d)))];
    const reports = [];
    for (const root of roots) {
        try {
            // One scan per project; the policy (ignores) of that project applies.
            const r = await scanProject(root, { minSeverity: 'low' });
            const state = loadState(); // re-read each time: a session hook may have written meanwhile
            const u = recordScan(state, root, r.findings);
            saveState(state);
            reports.push({ root, ...u });
        }
        catch (err) {
            reports.push({ root, firstRun: false, added: [], resolved: [], total: 0, error: err.message });
        }
    }
    const alert = reports.flatMap((p) => p.added.filter((e) => atLeast(e.severity, opts.min ?? loadPolicy(p.root).policy.minSeverity ?? 'moderate')));
    if (opts.json)
        log(JSON.stringify({ projects: reports, alert: alert.length }, null, 2));
    else
        log(formatWatch(dirs, roots, reports));
    if (opts.notify && alert.length) {
        const groups = groupEntries(alert);
        const top = groups[0].head;
        const title = `pkgguard: ${groups.length} newly vulnerable package${groups.length === 1 ? '' : 's'}`;
        const body = `${top.name}@${top.version} [${top.severity}] ${top.cve ?? top.advisory}${groups.length > 1 ? ` and ${groups.length - 1} more` : ''}. Open Claude Code in the project and ask it to fix them.`;
        notify(title, body);
    }
    return { reports, alert };
}
function formatWatch(dirs, roots, reports) {
    const base = dirs.length === 1 ? resolve(dirs[0]) : undefined;
    const name = (root) => (base && root !== base ? relative(base, root).replace(/\\/g, '/') : root);
    const lines = [`pkgguard watch — ${roots.length} project${roots.length === 1 ? '' : 's'} (${new Date().toLocaleString()})`];
    if (!roots.length)
        lines.push('No projects found (looked for git repositories and dependency files, 3 folders deep).');
    const quiet = [];
    const baseline = reports.filter((p) => p.firstRun && !p.error);
    if (baseline.length) {
        const vulnerable = baseline.filter((p) => p.total).map((p) => `${name(p.root)} (${p.total})`);
        const clean = baseline.filter((p) => !p.total).map((p) => name(p.root));
        lines.push('', `First run for ${baseline.length} project${baseline.length === 1 ? '' : 's'} — recorded as the baseline; later runs report only what changes.`);
        if (vulnerable.length)
            lines.push(`  Known vulnerable advisories: ${vulnerable.join(', ')}`);
        if (clean.length)
            lines.push(`  Clean: ${clean.join(', ')}`);
        lines.push('  `pkgguard scan <project>` lists them.');
    }
    for (const p of reports) {
        if (p.error)
            lines.push('', `${name(p.root)}: scan failed — ${p.error}`);
        else if (p.firstRun)
            continue;
        else if (p.added.length || p.resolved.length) {
            lines.push('', `${name(p.root)}:`);
            if (p.added.length)
                lines.push(`  NEW (${groupEntries(p.added).length} package${groupEntries(p.added).length === 1 ? '' : 's'}):`, ...formatEntries(p.added, 20).map((l) => `  ${l}`));
            if (p.resolved.length)
                lines.push(`  RESOLVED: ${groupEntries(p.resolved).map((g) => `${g.head.name}@${g.head.version}`).join(', ')}`);
        }
        else
            quiet.push(name(p.root));
    }
    if (quiet.length)
        lines.push('', `No change: ${quiet.join(', ')}`);
    return lines.join('\n');
}
