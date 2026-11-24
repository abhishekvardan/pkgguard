import { parseTomlTables, viaPaths } from './util.js';
/**
 * Cargo.lock. Packages without a registry `source` are the workspace's own crates;
 * their dependencies are the direct ones.
 */
export function parseCargoLock(text, source) {
    const pkgs = [];
    for (const t of parseTomlTables(text)) {
        if (!t.array || t.header !== 'package')
            continue;
        const src = String(t.values.source ?? '');
        pkgs.push({
            name: String(t.values.name ?? ''),
            version: String(t.values.version ?? ''),
            registry: src.startsWith('registry+') || src.startsWith('sparse+'),
            // "serde", "serde 1.0.1", "serde 1.0.1 (registry+...)"
            deps: (t.values.dependencies ?? []).map((d) => d.split(' ')[0]),
        });
    }
    const graph = new Map();
    for (const p of pkgs)
        graph.set(p.name, [...(graph.get(p.name) ?? []), ...p.deps]);
    const local = pkgs.filter((p) => !p.registry);
    const direct = new Set(local.flatMap((p) => p.deps));
    const paths = viaPaths(graph, direct);
    return pkgs
        .filter((p) => p.registry && p.version)
        .map((p) => {
        const isDirect = direct.has(p.name);
        const via = isDirect ? undefined : paths.get(p.name);
        return { ecosystem: 'crates.io', name: p.name, version: p.version, direct: isDirect, dev: false, source, tool: 'cargo', ...(via?.length ? { via } : {}) };
    });
}
