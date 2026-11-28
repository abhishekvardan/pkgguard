export declare const USER_AGENT = "pkgguard/0.3.0";
export declare class HttpError extends Error {
    status: number;
    constructor(status: number, url: string);
}
export interface FetchOpts {
    timeoutMs?: number;
    retries?: number;
    method?: string;
    body?: unknown;
    headers?: Record<string, string>;
}
/** JSON fetch with a timeout and a retry on network errors / 5xx / 429. 404 resolves to undefined. */
export declare function fetchJson<T = any>(url: string, opts?: FetchOpts): Promise<T | undefined>;
/** Run `fn` over `items` with at most `limit` in flight. */
export declare function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]>;
