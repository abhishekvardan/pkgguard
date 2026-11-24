import { cacheGet, cacheSet, HOUR } from './cache.js';
import { fetchJson } from './http.js';
import { compareVersions, isPrerelease, maxSatisfying } from './version.js';
/**
 * Package registry lookups, used to resolve what an unpinned install would actually get
 * (`npm i lodash`, `pip install requests`, `cargo add serde`). Each returns undefined
 * on any failure, and the caller then reports the package as not checked.
 */
const TTL = 1 * HOUR;
/** Go module proxy case-encoding: uppercase letters become "!" + lowercase. */
function goEscape(path) {
    return path.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}
async function cached(key, fn) {
    const hit = cacheGet(key, TTL);
    if (hit !== undefined)
        return hit;
    const v = await fn();
    if (v !== undefined)
        cacheSet(key, v);
    return v;
}
function stableMax(versions) {
    const stable = versions.filter((v) => !isPrerelease(v));
    const pool = stable.length ? stable : versions;
    return pool.sort(compareVersions).at(-1);
}
export async function latestVersion(ecosystem, name, opts = {}) {
    return cached(`latest|${ecosystem}|${name}`, async () => {
        try {
            switch (ecosystem) {
                case 'npm': {
                    const r = await fetchJson(`https://registry.npmjs.org/${name.replace('/', '%2F')}/latest`, opts);
                    return r?.version;
                }
                case 'PyPI': {
                    const r = await fetchJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, opts);
                    return r?.info?.version;
                }
                case 'crates.io': {
                    const r = await fetchJson(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`, opts);
                    return r?.crate?.max_stable_version || r?.crate?.max_version;
                }
                case 'Go': {
                    const r = await fetchJson(`https://proxy.golang.org/${goEscape(name)}/@latest`, opts);
                    return r?.Version;
                }
                case 'RubyGems': {
                    const r = await fetchJson(`https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}/latest.json`, opts);
                    return r?.version && r.version !== 'unknown' ? r.version : undefined;
                }
                case 'Packagist': {
                    const r = await fetchJson(`https://repo.packagist.org/p2/${name}.json`, opts);
                    const list = r?.packages?.[name] ?? [];
                    return stableMax(list.map((p) => String(p.version_normalized ?? p.version).replace(/^v/, '')));
                }
                case 'NuGet': {
                    const r = await fetchJson(`https://api.nuget.org/v3-flatcontainer/${name.toLowerCase()}/index.json`, opts);
                    return stableMax(r?.versions ?? []);
                }
                case 'Maven': {
                    const [g, a] = name.split(':');
                    if (!g || !a)
                        return undefined;
                    const q = encodeURIComponent(`g:"${g}" AND a:"${a}"`);
                    const r = await fetchJson(`https://search.maven.org/solrsearch/select?q=${q}&rows=1&wt=json`, opts);
                    return r?.response?.docs?.[0]?.latestVersion;
                }
            }
        }
        catch {
            return undefined;
        }
        return undefined;
    });
}
/** What `npm install name@range` would resolve to (npm-style ranges only). */
export async function npmResolve(name, range, opts = {}) {
    const doc = await cached(`npmversions|${name}`, async () => {
        try {
            const r = await fetchJson(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, {
                ...opts,
                headers: { accept: 'application/vnd.npm.install-v1+json' },
            });
            return r?.versions ? { versions: Object.keys(r.versions), tags: r['dist-tags'] ?? {} } : undefined;
        }
        catch {
            return undefined;
        }
    });
    if (!doc)
        return undefined;
    if (doc.tags[range])
        return doc.tags[range]; // dist-tag: latest, next, beta…
    return maxSatisfying(doc.versions, range);
}
