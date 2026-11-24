import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
/**
 * A tiny file-per-key cache shared by the MCP server and the hooks (separate processes),
 * so a key written by one is a hit for the other. Every operation is best-effort:
 * a broken cache only costs a network call.
 */
export function cacheDir() {
    return process.env.PKGGUARD_CACHE_DIR || join(homedir(), '.cache', 'pkgguard');
}
function fileFor(key) {
    const h = createHash('sha1').update(key).digest('hex');
    return join(cacheDir(), h.slice(0, 2), `${h}.json`);
}
export function cacheGet(key, ttlMs) {
    if (process.env.PKGGUARD_NO_CACHE === '1')
        return undefined;
    try {
        const raw = JSON.parse(readFileSync(fileFor(key), 'utf8'));
        if (Date.now() - raw.t > ttlMs)
            return undefined;
        return raw.v;
    }
    catch {
        return undefined;
    }
}
export function cacheSet(key, value) {
    if (process.env.PKGGUARD_NO_CACHE === '1')
        return;
    try {
        const file = fileFor(key);
        mkdirSync(join(file, '..'), { recursive: true });
        const tmp = `${file}.${process.pid}.tmp`;
        writeFileSync(tmp, JSON.stringify({ t: Date.now(), v: value }));
        renameSync(tmp, file);
    }
    catch {
        // ignore
    }
}
export const HOUR = 60 * 60 * 1000;
