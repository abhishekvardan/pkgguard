const PRE = {
    snapshot: -6,
    dev: -5,
    alpha: -4,
    a: -4,
    beta: -3,
    b: -3,
    milestone: -2,
    m: -2,
    rc: -1,
    c: -1,
    cr: -1,
    pre: -1,
    preview: -1,
};
const POST = { final: 0, ga: 0, release: 0, r: 1, post: 1, sp: 1, p: 1, pl: 1, patch: 1 };
function tokens(v) {
    const s = v.trim().replace(/^[vV](?=\d)/, '').replace(/\+.*$/, '').toLowerCase();
    const out = [];
    for (const m of s.matchAll(/\d+|[a-z]+/g)) {
        out.push(/^\d/.test(m[0]) ? Number(m[0]) : m[0]);
    }
    // Drop trailing release qualifiers ("1.0.Final" == "1.0").
    while (out.length > 1) {
        const last = out[out.length - 1];
        if (typeof last === 'string' && POST[last] === 0)
            out.pop();
        else
            break;
    }
    return out;
}
function wordRank(w) {
    return PRE[w] ?? POST[w];
}
/** Rank of what follows the end of the shorter version: <0 means "shorter is newer". */
function tailSign(t) {
    if (typeof t === 'number')
        return 1;
    const r = wordRank(t);
    return r !== undefined && r < 0 ? -1 : 1;
}
export function compareVersions(a, b) {
    const x = tokens(a);
    const y = tokens(b);
    const n = Math.max(x.length, y.length);
    for (let i = 0; i < n; i++) {
        const p = x[i];
        const q = y[i];
        // A missing number counts as 0 ("1.0" == "1.0.0"); a missing word defers to tailSign.
        if (p === undefined) {
            if (typeof q === 'number') {
                if (q === 0)
                    continue;
                return -1;
            }
            return -tailSign(q);
        }
        if (q === undefined) {
            if (typeof p === 'number') {
                if (p === 0)
                    continue;
                return 1;
            }
            return tailSign(p);
        }
        if (p === q)
            continue;
        if (typeof p === 'number' && typeof q === 'number')
            return p < q ? -1 : 1;
        if (typeof p === 'string' && typeof q === 'string') {
            const rp = wordRank(p);
            const rq = wordRank(q);
            if (rp !== undefined && rq !== undefined && rp !== rq)
                return rp < rq ? -1 : 1;
            return p < q ? -1 : 1;
        }
        // A word sorts below a number: 1.0.rc1 < 1.0.1, 1.0.post1 < 1.0.1
        return typeof p === 'string' ? -1 : 1;
    }
    return 0;
}
export function isPrerelease(v) {
    return tokens(v).some((t) => typeof t === 'string' && (PRE[t] !== undefined || POST[t] === undefined));
}
export function major(v) {
    const t = tokens(v)[0];
    return typeof t === 'number' ? t : undefined;
}
export function inRange(v, r) {
    if (r.introduced && r.introduced !== '0' && compareVersions(v, r.introduced) < 0)
        return false;
    if (r.fixed)
        return compareVersions(v, r.fixed) < 0;
    if (r.lastAffected)
        return compareVersions(v, r.lastAffected) <= 0;
    return true;
}
/** True for a plain, fully specified version such as 1.2.3, 2.0.0-rc.1 or v0.3.7. */
export function isExactVersion(spec) {
    const s = spec.trim();
    if (/(^|\.)[xX*](\.|$)/.test(s))
        return false; // 1.x, 1.2.*
    return /^[vV]?\d+(\.\d+)*([-.+_]?[A-Za-z][0-9A-Za-z.\-+_]*|[-+][0-9][0-9A-Za-z.\-+_]*)?$/.test(s);
}
/**
 * Highest version in `versions` satisfying an npm-style range. Supports the forms people
 * actually type: 1.2.3, ^1.2.3, ~1.2.3, 1, 1.2, 1.x, 1.2.x, *, >=1.2.3. Returns undefined
 * for anything more exotic so the caller can say it did not check.
 */
export function maxSatisfying(versions, range) {
    const r = range.trim();
    let lo;
    let hi; // exclusive
    let m;
    if (r === '' || r === '*' || r === 'x' || r === 'latest') {
        // no bounds
    }
    else if ((m = r.match(/^>=\s*v?(\d+(?:\.\d+){0,2}(?:-[\w.]+)?)$/))) {
        lo = m[1];
    }
    else if ((m = r.match(/^\^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(-[\w.]+)?$/))) {
        const [M, mi, p] = [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)];
        lo = `${M}.${mi}.${p}${m[4] ?? ''}`;
        if (M > 0 || m[2] === undefined)
            hi = `${M + 1}.0.0`;
        else if (mi > 0 || m[3] === undefined)
            hi = `0.${mi + 1}.0`;
        else
            hi = `0.0.${p + 1}`;
    }
    else if ((m = r.match(/^~v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(-[\w.]+)?$/))) {
        const [M, mi, p] = [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)];
        lo = `${M}.${mi}.${p}${m[4] ?? ''}`;
        hi = m[2] === undefined ? `${M + 1}.0.0` : `${M}.${mi + 1}.0`;
    }
    else if ((m = r.match(/^v?(\d+)(?:\.(\d+|[xX*]))?(?:\.([xX*]))?$/))) {
        const M = Number(m[1]);
        if (m[2] === undefined || /[xX*]/.test(m[2])) {
            lo = `${M}.0.0`;
            hi = `${M + 1}.0.0`;
        }
        else {
            lo = `${M}.${m[2]}.0`;
            hi = `${M}.${Number(m[2]) + 1}.0`;
        }
    }
    else if (isExactVersion(r)) {
        return versions.find((v) => compareVersions(v, r) === 0);
    }
    else {
        return undefined;
    }
    const allowPre = /-/.test(r);
    let best;
    for (const v of versions) {
        if (!allowPre && isPrerelease(v))
            continue;
        if (lo && compareVersions(v, lo) < 0)
            continue;
        if (hi && compareVersions(v, hi) >= 0)
            continue;
        if (!best || compareVersions(v, best) > 0)
            best = v;
    }
    return best;
}
