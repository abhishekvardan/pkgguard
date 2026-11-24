import { fixCommand } from './core/fix.js';
const LABEL = {
    critical: 'CRITICAL',
    high: 'HIGH',
    moderate: 'MODERATE',
    low: 'LOW',
    unknown: 'UNRATED',
};
export function cveOf(a) {
    return a.aliases.find((x) => x.startsWith('CVE-'));
}
export function advisoryTitle(a) {
    const cve = cveOf(a);
    return `${a.id}${cve ? ` (${cve})` : ''}`;
}
export function rangeText(r) {
    const from = r.introduced && r.introduced !== '0' ? `>=${r.introduced}` : '';
    const to = r.fixed ? `<${r.fixed}` : r.lastAffected ? `<=${r.lastAffected}` : '';
    return [from, to].filter(Boolean).join(', ') || 'all versions';
}
function fixedIn(a) {
    const fixes = [...new Set(a.ranges.map((r) => r.fixed).filter(Boolean))];
    return fixes.length ? `fixed in ${fixes.join(', ')}` : 'no fixed version';
}
export function countBySeverity(findings) {
    const counts = new Map();
    for (const f of findings)
        counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
    return ['critical', 'high', 'moderate', 'low', 'unknown']
        .filter((s) => counts.get(s))
        .map((s) => `${counts.get(s)} ${s === 'unknown' ? 'unrated' : s}`)
        .join(', ');
}
/** Multi-line description of one finding. */
export function formatFinding(f, maxAdvisories = 4) {
    const d = f.dep;
    const where = d.direct ? 'direct' : d.via?.length ? `transitive via ${[...d.via, d.name].join(' > ')}` : 'transitive';
    const lines = [`${LABEL[f.severity].padEnd(8)} ${d.ecosystem} ${d.name}@${d.version}  (${where}${d.dev ? ', dev' : ''}) — ${d.source}`];
    for (const a of f.advisories.slice(0, maxAdvisories)) {
        lines.push(`         ${advisoryTitle(a)} [${a.severity === 'unknown' ? 'unrated' : a.severity}] ${clip(a.summary, 200)} — ${fixedIn(a)}`);
    }
    if (f.advisories.length > maxAdvisories)
        lines.push(`         …and ${f.advisories.length - maxAdvisories} more advisories`);
    if (f.safeVersion)
        lines.push(`         → safe version: ${f.safeVersion}  —  ${fixCommand(d, f.safeVersion)}`);
    else if (f.noFix)
        lines.push('         → no fixed version exists for at least one advisory: consider replacing or isolating this package');
    else
        lines.push('         → no verified safe version (check the advisory for upgrade guidance)');
    return lines.join('\n');
}
export function formatScan(r, limit = 40) {
    const files = r.manifests.length;
    const head = r.findings.length
        ? `pkgguard: ${r.findings.length} vulnerable package${r.findings.length === 1 ? '' : 's'} in ${r.dependencies} dependencies (${files} file${files === 1 ? '' : 's'}) — ${countBySeverity(r.findings)}`
        : `pkgguard: no known vulnerabilities in ${r.dependencies} dependencies (${files} file${files === 1 ? '' : 's'}).`;
    const out = [head];
    if (files)
        out.push(`Scanned: ${r.manifests.map((m) => `${m.path} (${m.deps})`).join(', ')}`);
    const byFile = countByFile(r.findings);
    if (byFile.length > 1)
        out.push('By file:', ...byFile.map((g) => `  ${g.file}: ${g.counts}`));
    if (r.findings.length) {
        out.push('');
        for (const f of r.findings.slice(0, limit))
            out.push(formatFinding(f), '');
        if (r.findings.length > limit)
            out.push(`…and ${r.findings.length - limit} more vulnerable packages, less severe than the ones above (pass "min_severity", or a "path" to one project, to narrow the scan).`);
    }
    if (r.notes.length)
        out.push(...r.notes.map((n) => `Note: ${n}`));
    out.push('Source: OSV.dev');
    return out.join('\n').replace(/\n{3,}/g, '\n\n').trim();
}
/** One-line-per-package summary, for hooks where context is precious. */
export function formatBrief(findings, limit = 5) {
    const lines = findings.slice(0, limit).map((f) => {
        const a = f.advisories[0];
        const more = f.advisories.length > 1 ? ` +${f.advisories.length - 1} more` : '';
        const fix = f.safeVersion ? `use ${f.safeVersion} or later` : f.noFix ? 'no fix available' : 'see advisory';
        const d = f.dep;
        const how = [d.direct ? 'direct' : d.via?.length ? `via ${d.via.join(' > ')}` : 'transitive', d.dev ? 'dev-only' : '', d.source.startsWith('command') ? '' : d.source]
            .filter(Boolean)
            .join(', ');
        return `- ${d.ecosystem} ${d.name}@${d.version} [${f.severity}] (${how}): ${advisoryTitle(a)} ${a.summary}${more} — ${fix}`;
    });
    if (findings.length > limit)
        lines.push(`- …and ${findings.length - limit} more`);
    return lines.join('\n');
}
export function formatAdvisory(a, pkg) {
    const lines = [
        `${advisoryTitle(a)} — ${a.severity === 'unknown' ? 'unrated' : a.severity}${a.score !== undefined ? ` (CVSS ${a.score})` : ''}`,
        a.summary,
    ];
    if (a.aliases.length)
        lines.push(`Aliases: ${a.aliases.join(', ')}`);
    if (pkg)
        lines.push(`Affected ${pkg}: ${a.ranges.length ? a.ranges.map(rangeText).join(' | ') : a.versions.length ? `${a.versions.length} listed versions` : 'see advisory'}`);
    if (a.published)
        lines.push(`Published: ${a.published.slice(0, 10)}`);
    if (a.references.length)
        lines.push(`References: ${a.references.join(' ')}`);
    return lines.join('\n');
}
/** Vulnerable-package counts per lockfile/manifest, most findings first. */
export function countByFile(findings) {
    const groups = new Map();
    for (const f of findings)
        groups.set(f.dep.source, [...(groups.get(f.dep.source) ?? []), f]);
    return [...groups]
        .map(([file, fs]) => ({ file, vulnerable: fs.length, worst: fs[0].severity, counts: countBySeverity(fs) }))
        .sort((a, b) => b.vulnerable - a.vulnerable);
}
const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
/** Machine-readable form for MCP structuredContent. Advisories are capped so big scans stay small. */
export function findingJson(f, maxAdvisories = 3) {
    return {
        ecosystem: f.dep.ecosystem,
        name: f.dep.name,
        version: f.dep.version,
        direct: f.dep.direct,
        dev: f.dep.dev,
        via: f.dep.via,
        source: f.dep.source,
        severity: f.severity,
        safeVersion: f.safeVersion ?? null,
        noFix: f.noFix,
        fix: f.safeVersion ? fixCommand(f.dep, f.safeVersion) : null,
        advisoryCount: f.advisories.length,
        advisories: f.advisories.slice(0, maxAdvisories).map((a) => ({
            id: a.id,
            cve: cveOf(a) ?? null,
            severity: a.severity,
            score: a.score ?? null,
            summary: clip(a.summary, 200),
            affected: a.ranges.slice(0, 3).map(rangeText),
        })),
    };
}
