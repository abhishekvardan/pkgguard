import { isExactVersion } from '../core/version.js';
/** gradle.lockfile: `group:artifact:version=configuration,...` per line. */
export function parseGradleLock(text, source) {
    const out = [];
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line.startsWith('#') || line.startsWith('empty='))
            continue;
        const [coord, confs = ''] = line.split('=');
        const [g, a, v] = (coord ?? '').split(':');
        if (!g || !a || !v)
            continue;
        const dev = confs.split(',').every((c) => /test/i.test(c));
        out.push({ ecosystem: 'Maven', name: `${g}:${a}`, version: v, direct: false, dev, source, tool: 'gradle' });
    }
    return out;
}
/**
 * pom.xml — direct <dependency> entries with a literal or ${property} version.
 * Transitive dependencies need a Maven resolve and are not read.
 */
export function parsePom(text, source) {
    const xml = text.replace(/<!--[\s\S]*?-->/g, '');
    const props = new Map();
    const propsBlock = xml.match(/<properties>([\s\S]*?)<\/properties>/)?.[1] ?? '';
    for (const m of propsBlock.matchAll(/<([\w.\-]+)>\s*([^<]*?)\s*<\/\1>/g))
        props.set(m[1], m[2]);
    const projectVersion = xml.replace(/<parent>[\s\S]*?<\/parent>/, '').replace(/<dependencies>[\s\S]*$/, '').match(/<version>\s*([^<]+?)\s*<\/version>/)?.[1];
    if (projectVersion)
        props.set('project.version', projectVersion);
    const resolve = (v) => v.replace(/\$\{([^}]+)\}/g, (_, k) => props.get(k) ?? `\${${k}}`);
    const out = [];
    let unpinned = 0;
    const tag = (block, t) => block.match(new RegExp(`<${t}>\\s*([^<]+?)\\s*</${t}>`))?.[1];
    for (const m of xml.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
        const b = m[1];
        const g = tag(b, 'groupId');
        const a = tag(b, 'artifactId');
        const rawV = tag(b, 'version');
        if (!g || !a)
            continue;
        if (!rawV) {
            unpinned++;
            continue;
        }
        const v = resolve(rawV).replace(/^\[([^,\]]+)\]$/, '$1');
        if (v.includes('${') || !isExactVersion(v)) {
            unpinned++;
            continue;
        }
        const scope = tag(b, 'scope');
        out.push({ ecosystem: 'Maven', name: `${resolve(g)}:${resolve(a)}`, version: v, direct: true, dev: scope === 'test', source, tool: 'maven' });
    }
    return { deps: out, unpinned };
}
