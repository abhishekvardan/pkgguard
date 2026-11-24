export const USER_AGENT = 'pkgguard/0.2.1';

export class HttpError extends Error {
  constructor(
    public status: number,
    url: string,
  ) {
    super(`HTTP ${status} from ${url}`);
  }
}

export interface FetchOpts {
  timeoutMs?: number;
  retries?: number;
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

/** JSON fetch with a timeout and a retry on network errors / 5xx / 429. 404 resolves to undefined. */
export async function fetchJson<T = any>(url: string, opts: FetchOpts = {}): Promise<T | undefined> {
  const { timeoutMs = 15000, retries = 1, method = 'GET', body, headers = {} } = opts;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        method,
        headers: {
          'user-agent': USER_AGENT,
          accept: 'application/json',
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...headers,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 404) return undefined;
      if (res.ok) return (await res.json()) as T;
      lastErr = new HttpError(res.status, url);
      if (res.status < 500 && res.status !== 429) break;
    } catch (err) {
      lastErr = err;
      if ((err as Error)?.name === 'TimeoutError') break; // don't double a timeout
    }
    if (attempt < retries) await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
  }
  throw lastErr;
}

/** Run `fn` over `items` with at most `limit` in flight. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  });
  await Promise.all(workers);
  return out;
}
