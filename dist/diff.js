import { readFileSync } from 'node:fs';
import { maxSeverity } from './core/severity.js';
import { normalizeName } from './core/osv.js';
/**
 * A fingerprint names one advisory on one package version: `npm:lodash@4.17.15#GHSA-p6mc-m468-83gw`.
 * Comparing fingerprint sets tells what is new since an earlier scan — a newly published CVE
 * against a version you already had, or a vulnerable version that an install brought in.
 */
export function fingerprint(f, advisoryId) {
    return `${f.dep.ecosystem}:${normalizeName(f.dep.ecosystem, f.dep.name)}@${f.dep.version}#${advisoryId}`;
}
export function fingerprints(findings) {
    return [...new Set(findings.flatMap((f) => f.advisories.map((a) => fingerprint(f, a.id))))].sort();
}
export function diffFindings(baseline, findings) {
    const before = new Set(baseline);
    const now = new Set();
    const added = [];
    let unchanged = 0;
    for (const f of findings) {
        const fresh = f.advisories.filter((a) => {
            const fp = fingerprint(f, a.id);
            now.add(fp);
            if (before.has(fp)) {
                unchanged++;
                return false;
            }
            return true;
        });
        if (fresh.length)
            added.push({ ...f, advisories: fresh, severity: maxSeverity(fresh.map((a) => a.severity)) });
    }
    return { added, resolved: [...before].filter((fp) => !now.has(fp)).sort(), unchanged };
}
/** Read a baseline: the output of `pkgguard scan --json` (or any JSON with a `fingerprints` array). */
export function readBaseline(file) {
    const j = JSON.parse(readFileSync(file, 'utf8'));
    if (Array.isArray(j?.fingerprints))
        return j.fingerprints.map(String);
    if (Array.isArray(j?.findings)) {
        return j.findings.flatMap((f) => (f.advisories ?? []).map((a) => fingerprint({ dep: { ecosystem: f.ecosystem, name: f.name, version: f.version } }, a.id)));
    }
    throw new Error(`${file} is not a pkgguard baseline (expected the output of \`pkgguard scan --json\`).`);
}
/** "npm lodash 4.17.15 (GHSA-…)" for a fingerprint. */
export function describeFingerprint(fp) {
    const m = fp.match(/^([^:]+):(.+)@([^@#]+)#(.+)$/);
    return m ? `${m[1]} ${m[2]} ${m[3]} (${m[4]})` : fp;
}
