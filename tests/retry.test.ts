import { describe, expect, test } from "bun:test";
import { withBackoff } from "../src/retry.ts";

const noSleep = async () => {};

function statusFetch(...statuses: number[]): { fn: () => Promise<Response>; calls: () => number } {
  let i = 0;
  return {
    fn: async () => {
      const status = statuses[Math.min(i, statuses.length - 1)]!;
      i += 1;
      return new Response("", { status });
    },
    calls: () => i,
  };
}

describe("withBackoff", () => {
  test("retries on 503 up to the limit then succeeds", async () => {
    const { fn, calls } = statusFetch(503, 503, 200);
    const res = await withBackoff(fn, { retries: 2, sleep: noSleep });
    expect(res.status).toBe(200);
    expect(calls()).toBe(3);
  });

  test("returns the last transient response when retries are exhausted", async () => {
    const { fn, calls } = statusFetch(503);
    const res = await withBackoff(fn, { retries: 2, sleep: noSleep });
    expect(res.status).toBe(503);
    expect(calls()).toBe(3); // initial + 2 retries
  });

  test("does NOT retry on 400", async () => {
    const { fn, calls } = statusFetch(400, 200);
    const res = await withBackoff(fn, { retries: 2, sleep: noSleep });
    expect(res.status).toBe(400);
    expect(calls()).toBe(1);
  });

  test("does NOT retry on 401", async () => {
    const { fn, calls } = statusFetch(401, 200);
    const res = await withBackoff(fn, { retries: 2, sleep: noSleep });
    expect(res.status).toBe(401);
    expect(calls()).toBe(1);
  });

  test("retries a network error then succeeds", async () => {
    let i = 0;
    const fn = async () => {
      i += 1;
      if (i < 2) throw new Error("ECONNRESET");
      return new Response("", { status: 200 });
    };
    const res = await withBackoff(fn, { retries: 2, sleep: noSleep });
    expect(res.status).toBe(200);
    expect(i).toBe(2);
  });

  test("does NOT retry an AbortError (timeout)", async () => {
    let i = 0;
    const fn = async () => {
      i += 1;
      throw new DOMException("aborted", "AbortError");
    };
    await expect(withBackoff(fn, { retries: 2, sleep: noSleep })).rejects.toThrow();
    expect(i).toBe(1);
  });
});
