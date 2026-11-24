import { normalizeName } from '../core/osv.js';
import { inlineField, parseTomlTables, readJson, viaPaths } from './util.js';
const norm = (n) => normalizeName('PyPI', n);
/** Requirement name from a PEP 508 string: "requests[security]>=2; python_version<'3'" -> "requests". */
export function reqName(spec) {
    const m = spec.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
    return m ? m[1] : undefined;
}
function isDevFile(source) {
    return /(^|[\\/._-])(dev|test|tests|testing|lint|docs|ci)([\\/._-]|$)/i.test(source.replace(/requirements/i, ''));
}
/**
 * requirements*.txt. Only `==` / `===` pins are checked. pip-compile "# via" annotations
 * are used to tell direct from transitive dependencies.
 */
export function parseRequirements(text, source) {
    const deps = [];
    let unpinned = 0;
    const dev = isDevFile(source);
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i];
        while (line.endsWith('\\') && i + 1 < lines.length)
            line = line.slice(0, -1) + ' ' + lines[++i];
        const body = line.replace(/\s+#.*$/, '').replace(/^#.*$/, '').trim();
        if (!body || body.startsWith('-') || /^(git\+|https?:|file:|\.|\/)/.test(body))
            continue;
        const spec = body.split(/\s+--/)[0].split(';')[0].trim();
        const m = spec.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s,;]+)$/);
        if (!m) {
            if (reqName(spec))
                unpinned++;
            continue;
        }
        // pip-compile: following comment lines say who pulled this in
        const via = [];
        let inVia = false;
        for (let j = i + 1; j < lines.length; j++) {
            const c = lines[j].trim();
            if (!c.startsWith('#'))
                break;
            const t = c.replace(/^#\s*/, '');
            if (/^via(\s|$)/.test(t)) {
                inVia = true;
                const rest = t.slice(3).trim();
                if (rest)
                    via.push(rest);
            }
            else if (inVia && t)
                via.push(t);
        }
        const parents = via.filter((v) => !v.startsWith('-'));
        const direct = !via.length || via.some((v) => v.startsWith('-r') || v.startsWith('-c'));
        deps.push({
            ecosystem: 'PyPI',
            name: m[1],
            version: m[3],
            direct,
            dev,
            source,
            tool: 'pip',
            ...(!direct && parents.length ? { via: [parents[0]] } : {}),
        });
    }
    return { deps, unpinned };
}
/** Names declared in pyproject.toml: [project] dependencies, poetry tables, dependency groups. */
export function readPyproject(text) {
    const deps = new Set();
    const dev = new Set();
    if (!text)
        return { deps, dev };
    for (const t of parseTomlTables(text)) {
        const h = t.header;
        if (h === 'project') {
            for (const s of t.values.dependencies ?? []) {
                const n = reqName(s);
                if (n)
                    deps.add(norm(n));
            }
        }
        else if (h === 'project.optional-dependencies') {
            for (const list of Object.values(t.values))
                for (const s of Array.isArray(list) ? list : []) {
                    const n = reqName(s);
                    if (n)
                        deps.add(norm(n));
                }
        }
        else if (h === 'dependency-groups' || h === 'tool.uv') {
            const lists = h === 'tool.uv' ? [t.values['dev-dependencies']] : Object.values(t.values);
            for (const list of lists)
                for (const s of Array.isArray(list) ? list : []) {
                    const n = reqName(s);
                    if (n)
                        dev.add(norm(n));
                }
        }
        else if (h === 'tool.poetry.dependencies') {
            for (const k of Object.keys(t.values))
                if (k !== 'python')
                    deps.add(norm(k));
        }
        else if (/^tool\.poetry\.(dev-dependencies|group\.[^.]+\.dependencies)$/.test(h)) {
            for (const k of Object.keys(t.values))
                dev.add(norm(k));
        }
    }
    for (const d of deps)
        dev.delete(d);
    return { deps, dev };
}
function finishLock(pkgs, manifest, source, tool) {
    const graph = new Map();
    for (const p of pkgs)
        graph.set(norm(p.name), p.children.map(norm));
    const known = manifest.deps.size + manifest.dev.size > 0;
    const paths = viaPaths(graph, [...manifest.deps, ...manifest.dev]);
    const prod = viaPaths(graph, [...manifest.deps]);
    return pkgs
        .filter((p) => !p.skip && p.version)
        .map((p) => {
        const n = norm(p.name);
        const direct = known ? manifest.deps.has(n) || manifest.dev.has(n) : true;
        const dev = p.category ? p.category === 'dev' : known ? !prod.has(n) && (manifest.dev.has(n) || paths.has(n)) : false;
        const via = direct ? undefined : paths.get(n);
        return { ecosystem: 'PyPI', name: p.name, version: p.version, direct, dev, source, tool, ...(via?.length ? { via } : {}) };
    });
}
/** poetry.lock (any version). */
export function parsePoetryLock(text, source, pyproject) {
    const pkgs = [];
    let cur;
    for (const t of parseTomlTables(text)) {
        if (t.array && t.header === 'package') {
            const groups = t.values.groups; // poetry 2
            const category = Array.isArray(groups) ? (groups.includes('main') ? 'main' : 'dev') : t.values.category;
            cur = {
                name: String(t.values.name ?? ''),
                version: String(t.values.version ?? ''),
                category,
                children: [],
                skip: false,
            };
            pkgs.push(cur);
        }
        else if (cur && t.header === 'package.dependencies') {
            cur.children.push(...Object.keys(t.values));
        }
        else if (cur && t.header === 'package.source') {
            const type = String(t.values.type ?? '');
            if (type && type !== 'legacy')
                cur.skip = true; // git / directory / file / url
        }
    }
    return finishLock(pkgs, readPyproject(pyproject), source, 'poetry');
}
/** uv.lock. The project itself (editable / virtual source) supplies the direct dependencies. */
export function parseUvLock(text, source, pyproject) {
    const pkgs = [];
    const manifest = readPyproject(pyproject);
    let cur;
    let curIsRoot = false;
    const names = (list) => (Array.isArray(list) ? list : []).map((x) => (String(x).startsWith('{') ? inlineField(String(x), 'name') : reqName(String(x)))).filter((x) => !!x);
    for (const t of parseTomlTables(text)) {
        if (t.array && t.header === 'package') {
            const src = String(t.values.source ?? '');
            curIsRoot = /\b(editable|virtual)\s*=/.test(src);
            const local = curIsRoot || /\b(path|directory|git|url)\s*=/.test(src);
            cur = { name: String(t.values.name ?? ''), version: String(t.values.version ?? ''), children: names(t.values.dependencies), skip: local };
            pkgs.push(cur);
            if (curIsRoot && !pyproject)
                for (const n of cur.children)
                    manifest.deps.add(norm(n));
        }
        else if (cur && /^package\.(optional-dependencies|dev-dependencies)$/.test(t.header)) {
            const isDev = t.header.endsWith('dev-dependencies');
            for (const list of Object.values(t.values)) {
                const ns = names(list);
                cur.children.push(...ns);
                if (curIsRoot && !pyproject)
                    for (const n of ns)
                        (isDev ? manifest.dev : manifest.deps).add(norm(n));
            }
        }
    }
    for (const d of manifest.deps)
        manifest.dev.delete(d);
    return finishLock(pkgs, manifest, source, 'uv');
}
/** Pipfile.lock (JSON). "develop" packages are dev. */
export function parsePipfileLock(text, source, pipfile) {
    const j = readJson(text);
    const declared = new Set();
    if (pipfile) {
        let section = '';
        for (const line of pipfile.split(/\r?\n/)) {
            const h = line.match(/^\s*\[([^\]]+)\]/);
            if (h)
                section = h[1];
            else if (section === 'packages' || section === 'dev-packages') {
                const m = line.match(/^\s*("?)([A-Za-z0-9._-]+)\1\s*=/);
                if (m)
                    declared.add(norm(m[2]));
            }
        }
    }
    const out = [];
    for (const [section, dev] of [['default', false], ['develop', true]]) {
        for (const [name, p] of Object.entries(j[section] ?? {})) {
            const v = String(p?.version ?? '').replace(/^===?/, '');
            if (!v || p?.git || p?.path || p?.file)
                continue;
            out.push({ ecosystem: 'PyPI', name, version: v, direct: pipfile ? declared.has(norm(name)) : true, dev, source, tool: 'pipenv' });
        }
    }
    return out;
}
