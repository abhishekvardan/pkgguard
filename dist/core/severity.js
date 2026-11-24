import { SEVERITY_RANK } from '../types.js';
const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
};
/** CVSS 3.1 "Roundup": smallest number with one decimal that is >= x. */
function roundup(x) {
    const i = Math.round(x * 100000);
    return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}
/** Base score of a CVSS v3.x vector such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. */
export function cvss3Score(vector) {
    if (!/^CVSS:3\.[01]\//.test(vector))
        return undefined;
    const m = {};
    for (const part of vector.split('/').slice(1)) {
        const [k, v] = part.split(':');
        if (k && v)
            m[k] = v;
    }
    const changed = m.S === 'C';
    const av = W.AV[m.AV ?? ''];
    const ac = W.AC[m.AC ?? ''];
    const ui = W.UI[m.UI ?? ''];
    const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR ?? ''];
    const c = W.CIA[m.C ?? ''];
    const i = W.CIA[m.I ?? ''];
    const a = W.CIA[m.A ?? ''];
    if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined))
        return undefined;
    const iss = 1 - (1 - c) * (1 - i) * (1 - a);
    const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    if (impact <= 0)
        return 0;
    const exploitability = 8.22 * av * ac * pr * ui;
    return changed ? roundup(Math.min(1.08 * (impact + exploitability), 10)) : roundup(Math.min(impact + exploitability, 10));
}
export function severityFromScore(score) {
    if (score >= 9)
        return 'critical';
    if (score >= 7)
        return 'high';
    if (score >= 4)
        return 'moderate';
    if (score > 0)
        return 'low';
    return 'unknown';
}
/** Normalise the labels different databases use (GHSA "MODERATE", PyPA "MEDIUM", …). */
export function severityFromLabel(label) {
    if (typeof label !== 'string')
        return undefined;
    switch (label.trim().toLowerCase()) {
        case 'critical':
            return 'critical';
        case 'high':
        case 'important':
            return 'high';
        case 'moderate':
        case 'medium':
            return 'moderate';
        case 'low':
        case 'minor':
            return 'low';
        default:
            return undefined;
    }
}
/**
 * Severity of an OSV record. Prefers the database's own label (GitHub's reviewed rating),
 * then a computed CVSS v3 score. CVSS v4 vectors are not computed; they rarely appear
 * without a label alongside.
 */
export function osvSeverity(vuln) {
    let score;
    for (const s of vuln?.severity ?? []) {
        if (typeof s?.score !== 'string')
            continue;
        const computed = cvss3Score(s.score);
        if (computed !== undefined)
            score = Math.max(score ?? 0, computed);
        else if (/^\d+(\.\d+)?$/.test(s.score))
            score = Math.max(score ?? 0, Number(s.score));
    }
    const labels = [vuln?.database_specific?.severity];
    for (const a of vuln?.affected ?? []) {
        labels.push(a?.ecosystem_specific?.severity, a?.database_specific?.severity);
    }
    for (const l of labels) {
        const sev = severityFromLabel(l);
        if (sev)
            return { severity: sev, score };
    }
    return { severity: score !== undefined ? severityFromScore(score) : 'unknown', score };
}
export function maxSeverity(list) {
    let best = 'unknown';
    let rank = -1;
    for (const s of list) {
        // 'unknown' and 'moderate' share a rank; prefer the real label.
        const r = SEVERITY_RANK[s] + (s === 'unknown' ? 0 : 0.5);
        if (r > rank) {
            rank = r;
            best = s;
        }
    }
    return best;
}
export function atLeast(sev, min) {
    return SEVERITY_RANK[sev] >= SEVERITY_RANK[min];
}
export function parseSeverity(s, fallback) {
    if (!s)
        return fallback;
    return severityFromLabel(s) ?? (s.toLowerCase() === 'unknown' ? 'unknown' : fallback);
}
