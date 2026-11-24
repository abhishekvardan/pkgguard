import { advisoriesFor } from './osv.js';
import { compareVersions, inRange } from './version.js';
/**
 * The smallest version above `current` that is outside every advisory's affected range.
 * Picking the nearest fix per advisory keeps the upgrade within the same major whenever
 * the maintainers backported one.
 */
export function pickFix(current, advisories) {
    let target;
    for (const adv of advisories) {
        const containing = adv.ranges.filter((r) => inRange(current, r));
        let fix;
        if (containing.length) {
            const fixes = containing.map((r) => r.fixed).filter((f) => !!f);
            if (fixes.length !== containing.length)
                return { noFix: true };
            fix = fixes.sort(compareVersions).at(-1);
        }
        else {
            // OSV matched it (often via an explicit version list) but our comparator found no
            // containing range: take the nearest fix above the current version.
            fix = adv.ranges
                .map((r) => r.fixed)
                .filter((f) => !!f && compareVersions(f, current) > 0)
                .sort(compareVersions)[0];
            if (!fix)
                return { noFix: true };
        }
        if (!target || compareVersions(fix, target) > 0)
            target = fix;
    }
    return { version: target, noFix: false };
}
/**
 * Fill in `safeVersion` on every finding: propose a fix, ask OSV whether that version is
 * itself affected by something else, and step forward again if so (at most 4 rounds).
 */
export async function resolveSafeVersions(findings, opts = {}) {
    let pending = findings.map((f) => ({ f, current: f.dep.version, advisories: f.advisories }));
    for (let round = 0; round < 4 && pending.length; round++) {
        const asks = [];
        const candidates = [];
        for (const p of pending) {
            const { version, noFix } = pickFix(p.current, p.advisories);
            if (noFix || !version) {
                p.f.noFix = p.f.noFix || noFix;
                continue;
            }
            asks.push(p);
            candidates.push(version);
        }
        if (!asks.length)
            return;
        let results;
        try {
            results = await advisoriesFor(asks.map((p, i) => ({ ecosystem: p.f.dep.ecosystem, name: p.f.dep.name, version: candidates[i] })), opts);
        }
        catch {
            return; // offline: leave safeVersion unset rather than guess
        }
        pending = [];
        asks.forEach((p, i) => {
            const still = results[i] ?? [];
            if (!still.length)
                p.f.safeVersion = candidates[i];
            else
                pending.push({ f: p.f, current: candidates[i], advisories: still });
        });
    }
}
function quote(s) {
    return /[\s<>=^~|&;]/.test(s) ? `"${s}"` : s;
}
/** The command (or edit) that moves this dependency to `safe`. */
export function fixCommand(dep, safe) {
    const { name, direct, dev, tool } = dep;
    const D = dev ? ' -D' : '';
    switch (tool) {
        case 'npm':
            return direct ? `npm install${D} ${name}@^${safe}` : `add "overrides": { "${name}": "^${safe}" } to package.json, then npm install`;
        case 'pnpm':
            return direct ? `pnpm add${D} ${name}@^${safe}` : `add "pnpm": { "overrides": { "${name}": "^${safe}" } } to package.json, then pnpm install`;
        case 'yarn':
            return direct ? `yarn add${D} ${name}@^${safe}` : `add "resolutions": { "${name}": "^${safe}" } to package.json, then yarn install`;
        case 'pip':
            return `set ${name}==${safe} in ${dep.source}`;
        case 'poetry':
            return direct ? `poetry add ${quote(`${name}@^${safe}`)}${dev ? ' --group dev' : ''}` : `poetry update ${name}  (needs ${name}>=${safe})`;
        case 'uv':
            return direct ? `uv add ${quote(`${name}>=${safe}`)}${dev ? ' --dev' : ''}` : `uv lock --upgrade-package ${quote(`${name}>=${safe}`)}`;
        case 'pipenv':
            return `pipenv install ${quote(`${name}>=${safe}`)}${dev ? ' --dev' : ''}`;
        case 'go':
            return `go get ${name}@v${safe.replace(/^v/, '')} && go mod tidy`;
        case 'cargo':
            return `cargo update -p ${name} --precise ${safe}`;
        case 'bundler':
            return direct ? `set gem "${name}", ">= ${safe}" in Gemfile, then bundle update ${name}` : `bundle update --conservative ${name}`;
        case 'composer':
            return direct ? `composer require ${name}:^${safe}` : `composer update ${name} --with-dependencies`;
        case 'nuget':
            return `dotnet add package ${name} --version ${safe}`;
        case 'maven':
            return `set <version>${safe}</version> for ${name} in ${dep.source}${direct ? '' : ' (or pin it in <dependencyManagement>)'}`;
        case 'gradle':
            return `set ${name}:${safe} in build.gradle, then ./gradlew dependencies --write-locks`;
    }
}
