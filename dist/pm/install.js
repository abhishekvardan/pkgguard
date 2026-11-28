import { atLeast, parseSeverity } from '../core/severity.js';
import { countBySeverity, formatBrief } from '../format.js';
import { loadPolicy } from '../policy.js';
import { scanProject } from '../scan.js';
import { detectManager } from './detect.js';
import { runCmd, showCmd, syncCommand } from './run.js';
export async function runInstall(opts) {
    const log = opts.log ?? ((s) => console.error(s));
    const det = detectManager(opts.cwd, opts.pm);
    if (!det) {
        log('pkgguard: no project here. Pass --pm to choose a package manager.');
        return 2;
    }
    const { manager, root } = det;
    const { policy, warnings } = loadPolicy(root);
    warnings.forEach((w) => log(`pkgguard: ${w}`));
    const failOn = opts.failOn ?? parseSeverity(process.env.PKGGUARD_FAIL_ON, policy.failOn ?? 'high');
    const sync = syncCommand(manager, root, opts.ci, opts.extra);
    if (!sync) {
        log(`pkgguard: nothing to install for ${manager} here (no requirements file).`);
        return 2;
    }
    const gate = async (when) => {
        const r = await scanProject(root, { minSeverity: 'low' });
        if (!r.dependencies)
            return undefined;
        const bad = r.findings.filter((f) => atLeast(f.severity, failOn));
        const below = r.findings.length - bad.length;
        if (bad.length) {
            log(`pkgguard: the ${when === 'before' ? 'lockfile pins' : 'install resolved'} ${bad.length} package version(s) with ${failOn}+ vulnerabilities (${countBySeverity(bad)}):\n${formatBrief(bad, 10)}`);
            if (when === 'before' && !opts.allowVulnerable) {
                log(`pkgguard: not installing. Fix them first (\`pkgguard scan\` lists the commands, or ask Claude to /pkgguard:fix), lower "failOn" in .pkgguard.json, or pass --allow-vulnerable.`);
                return 1;
            }
            if (when === 'after')
                return 1;
        }
        if (below)
            log(`pkgguard: ${below} vulnerable package(s) below "${failOn}" — see \`pkgguard scan\`.`);
        return 0;
    };
    const pre = await gate('before').catch((err) => {
        log(`pkgguard: could not check before installing (${err.message}).`);
        return undefined;
    });
    if (pre === 1)
        return 1;
    log(`pkgguard: ${showCmd(sync)}`);
    const code = runCmd(sync, root);
    if (code !== 0)
        return code;
    if (pre === undefined) {
        // No lockfile before: check what got resolved.
        const post = await gate('after').catch(() => 0);
        return post ?? 0;
    }
    return 0;
}
