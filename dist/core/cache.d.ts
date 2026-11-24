/**
 * A tiny file-per-key cache shared by the MCP server and the hooks (separate processes),
 * so a key written by one is a hit for the other. Every operation is best-effort:
 * a broken cache only costs a network call.
 */
export declare function cacheDir(): string;
export declare function cacheGet<T>(key: string, ttlMs: number): T | undefined;
export declare function cacheSet(key: string, value: unknown): void;
export declare const HOUR: number;
