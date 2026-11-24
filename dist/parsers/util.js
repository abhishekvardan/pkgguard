/**
 * Shared helpers for lockfile parsers. Deliberately small, dependency-free readers that
 * understand exactly the subset of YAML / TOML that lockfiles use.
 */
/** Shortest chain from any root to each node, excluding the node itself: name -> [direct, ..., parent]. */
export function viaPaths(graph, roots) {
    const out = new Map();
    const queue = [];
    for (const r of roots) {
        if (!out.has(r)) {
            out.set(r, []);
            queue.push(r);
        }
    }
    while (queue.length) {
        const cur = queue.shift();
        const path = out.get(cur);
        for (const child of graph.get(cur) ?? []) {
            if (out.has(child))
                continue;
            out.set(child, [...path, cur]);
            queue.push(child);
        }
    }
    return out;
}
export function unquote(s) {
    const t = s.trim();
    if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")))
        return t.slice(1, -1);
    return t;
}
/**
 * Block-style YAML mapping reader (enough for pnpm-lock.yaml): nested maps of scalars.
 * Sequences become arrays of scalars; flow collections stay strings.
 */
export function parseSimpleYaml(text) {
    const root = {};
    const stack = [{ indent: -1, obj: root }];
    let pendingKey;
    for (const raw of text.split(/\r?\n/)) {
        if (!raw.trim() || raw.trimStart().startsWith('#'))
            continue;
        const indent = raw.length - raw.trimStart().length;
        const line = raw.trim();
        while (stack.length > 1 && indent <= stack[stack.length - 1].indent)
            stack.pop();
        if (line.startsWith('- ')) {
            if (pendingKey && indent >= pendingKey.indent) {
                const p = pendingKey.parent;
                if (!Array.isArray(p[pendingKey.key]))
                    p[pendingKey.key] = [];
                p[pendingKey.key].push(unquote(line.slice(2)));
            }
            continue;
        }
        // key: value  — keys may be quoted and contain ':' inside quotes
        let key;
        let rest;
        if (line.startsWith("'") || line.startsWith('"')) {
            const q = line[0];
            const end = line.indexOf(q, 1);
            if (end < 0)
                continue;
            key = line.slice(1, end);
            rest = line.slice(end + 1).replace(/^\s*:/, '');
        }
        else {
            const m = line.match(/^([^:]+?):(?:\s+(.*))?$/) ?? line.match(/^(.+?):$/);
            if (!m)
                continue;
            key = m[1];
            rest = m[2] ?? '';
        }
        const parent = stack[stack.length - 1].obj;
        const value = rest.trim();
        if (value === '' || value === '|' || value === '>') {
            const child = {};
            parent[key] = child;
            stack.push({ indent, obj: child });
            pendingKey = { parent, key, indent };
        }
        else {
            parent[key] = unquote(value);
            pendingKey = undefined;
        }
    }
    return root;
}
/**
 * Line-oriented TOML reader for lockfiles: returns tables in file order. Values are raw
 * strings (quotes removed); arrays become string arrays; inline tables stay raw text.
 */
export function parseTomlTables(text) {
    const tables = [{ header: '', array: false, values: {} }];
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#'))
            continue;
        let m = line.match(/^\[\[\s*([^\]]+?)\s*\]\]$/);
        if (m) {
            tables.push({ header: m[1], array: true, values: {} });
            continue;
        }
        m = line.match(/^\[\s*([^\]]+?)\s*\]$/);
        if (m) {
            tables.push({ header: m[1], array: false, values: {} });
            continue;
        }
        m = line.match(/^("[^"]+"|'[^']+'|[A-Za-z0-9_.\-]+)\s*=\s*(.*)$/);
        if (!m)
            continue;
        const k = unquote(m[1]);
        let v = m[2];
        const cur = tables[tables.length - 1];
        if (v.startsWith('[')) {
            // Possibly multi-line array: read until brackets balance.
            let depth = 0;
            let buf = '';
            for (;;) {
                for (const ch of v) {
                    if (ch === '[')
                        depth++;
                    else if (ch === ']')
                        depth--;
                }
                buf += v + '\n';
                if (depth <= 0 || i + 1 >= lines.length)
                    break;
                v = lines[++i].replace(/#.*$/, '');
            }
            cur.values[k] = splitTomlArray(buf.trim());
        }
        else if (v.startsWith('"""')) {
            let buf = v.slice(3);
            while (!buf.includes('"""') && i + 1 < lines.length)
                buf += '\n' + lines[++i];
            cur.values[k] = buf.replace(/"""[\s\S]*$/, '');
        }
        else {
            cur.values[k] = v.startsWith('{') ? v : unquote(v.replace(/\s+#.*$/, ''));
        }
    }
    return tables;
}
/** Split the inside of a TOML array into top-level items, keeping inline tables as raw text. */
function splitTomlArray(s) {
    const inner = s.replace(/^\[/, '').replace(/\]\s*$/, '');
    const items = [];
    let depth = 0;
    let quote;
    let cur = '';
    for (const ch of inner) {
        if (quote) {
            cur += ch;
            if (ch === quote)
                quote = undefined;
            continue;
        }
        if (ch === '"' || ch === "'") {
            quote = ch;
            cur += ch;
        }
        else if (ch === '{' || ch === '[') {
            depth++;
            cur += ch;
        }
        else if (ch === '}' || ch === ']') {
            depth--;
            cur += ch;
        }
        else if (ch === ',' && depth === 0) {
            if (cur.trim())
                items.push(cur.trim());
            cur = '';
        }
        else
            cur += ch;
    }
    if (cur.trim())
        items.push(cur.trim());
    return items.map((x) => (x.startsWith('{') ? x : unquote(x)));
}
/** Read `key = "value"` from a TOML inline table such as `{ name = "x", version = "1" }`. */
export function inlineField(inline, key) {
    const m = inline.match(new RegExp(`(?:^|[{,\\s])${key.replace(/[-.]/g, '\\$&')}\\s*=\\s*("[^"]*"|'[^']*'|[^,}\\s]+)`));
    return m ? unquote(m[1]) : undefined;
}
export function readJson(text) {
    return JSON.parse(text.replace(/^﻿/, ''));
}
