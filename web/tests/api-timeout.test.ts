import assert from "node:assert/strict";
import test from "node:test";

test("bounds a stalled API read and reports a timeout", async () => {
  const originalFetch = globalThis.fetch;
  const originalWindow = (globalThis as Record<string, unknown>).window;
  (globalThis as Record<string, unknown>).window = {
    setTimeout,
    clearTimeout,
    localStorage: { getItem: () => null, setItem: () => undefined, removeItem: () => undefined },
  };
  try {
    const { api, APIError } = await import("../src/api.ts");
    globalThis.fetch = ((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
    })) as typeof fetch;
    await assert.rejects(
      api("/api/v1/config", {}, "", 10),
      (error: unknown) => error instanceof APIError && error.code === "TIMEOUT",
    );
  } finally {
    globalThis.fetch = originalFetch;
    if (originalWindow === undefined) delete (globalThis as Record<string, unknown>).window;
    else (globalThis as Record<string, unknown>).window = originalWindow;
  }
});
