// Bounded exponential backoff for transient upstream failures.
//
// Used inside UpstreamClient.send to give network blips and transient HTTP
// statuses (408/429/502/503/504) a few retries. Does NOT retry on 401 (the
// DPoP/nonce recovery in upstream.ts owns that) or any other 4xx, and does NOT
// retry a deliberate timeout (AbortError) — that deadline has already passed.
export interface BackoffOptions {
  retries?: number;
  baseMs?: number;
  /** Injectable delay (tests pass a no-op). */
  sleep?: (ms: number) => Promise<void>;
}

const TRANSIENT_STATUS = new Set([408, 429, 502, 503, 504]);

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Invoke `fn` (a fetch-like call returning a Response), retrying on transient
 * statuses and network errors with exponential backoff. Returns the last
 * Response once retries are exhausted; rethrows the last error on persistent
 * network failure.
 */
export async function withBackoff(
  fn: () => Promise<Response>,
  opts: BackoffOptions = {},
): Promise<Response> {
  const retries = opts.retries ?? 2;
  const baseMs = opts.baseMs ?? 200;
  const sleep = opts.sleep ?? defaultSleep;

  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const res = await fn();
      if (attempt < retries && TRANSIENT_STATUS.has(res.status)) {
        await sleep(baseMs * 2 ** attempt);
        continue;
      }
      return res;
    } catch (err) {
      lastError = err;
      const isAbort = err instanceof Error && err.name === "AbortError";
      if (isAbort || attempt >= retries) throw err;
      await sleep(baseMs * 2 ** attempt);
    }
  }
  throw lastError; // unreachable: the loop returns or throws
}
