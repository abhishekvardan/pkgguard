/**
 * go.mod. Since Go 1.17 it lists every module in the build (indirect ones marked
 * `// indirect`), so go.sum — which also holds versions no longer used — is not read.
 * `replace` directives pointing at another module version are applied; local paths are skipped.
 */
export function parseGoMod(text, source) {
    const requires = [];
    const replaces = new Map();
    let block;
    const handle = (kind, body) => {
        const indirect = /\/\/\s*indirect/.test(body);
        const s = body.replace(/\/\/.*$/, '').trim();
        if (!s)
            return;
        if (kind === 'require') {
            const [name, version] = s.split(/\s+/);
            if (name && version)
                requires.push({ name, version, indirect });
        }
        else {
            const [lhs, rhs] = s.split('=>').map((x) => x.trim());
            if (!lhs || !rhs)
                return;
            const [from, fromVer] = lhs.split(/\s+/);
            const [to, toVer] = rhs.split(/\s+/);
            const target = to && toVer ? { name: to, version: toVer } : null; // local path => null
            replaces.set(fromVer ? `${from}@${fromVer}` : from, target);
        }
    };
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (block) {
            if (line.startsWith(')'))
                block = undefined;
            else
                handle(block, line);
            continue;
        }
        const m = line.match(/^(require|replace)\s*(\(|.*)$/);
        if (!m)
            continue;
        if (m[2] === '(')
            block = m[1];
        else
            handle(m[1], m[2]);
    }
    const out = [];
    for (const r of requires) {
        let target = replaces.has(`${r.name}@${r.version}`)
            ? replaces.get(`${r.name}@${r.version}`)
            : replaces.get(r.name);
        if (target === null)
            continue;
        const name = target?.name ?? r.name;
        const version = (target?.version ?? r.version).replace(/^v/, '');
        out.push({ ecosystem: 'Go', name, version, direct: !r.indirect, dev: false, source, tool: 'go' });
    }
    return out;
}
