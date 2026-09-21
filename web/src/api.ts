type APIEnvelope<T> = {
  success: boolean;
  data?: T;
  error?: { code?: string; message?: string; details?: string[] };
};

export class APIError extends Error {
  status: number;
  code: string;
  details: string[];

  constructor(status: number, code: string, message: string, details: string[] = []) {
    super(message);
    this.name = "APIError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const TOKEN_KEY = "ngfw.console.token";
export const DEFAULT_READ_TIMEOUT_MS = 8_000;
export const DEFAULT_WRITE_TIMEOUT_MS = 95_000;

export function storedToken(): string {
  return window.localStorage.getItem(TOKEN_KEY) ?? "";
}

export function persistToken(token: string): void {
  if (token) window.localStorage.setItem(TOKEN_KEY, token);
  else window.localStorage.removeItem(TOKEN_KEY);
}

export async function api<T>(path: string, init: RequestInit = {}, token = storedToken(), timeoutMs?: number): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body != null && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const method = (init.method ?? "GET").toUpperCase();
  // Runtime-backed reads can wait on a bounded engine IPC query. Do not let
  // one stalled upstream request hold the dashboard forever; callers can
  // override this for a known longer operation.
  const timeout = timeoutMs ?? (method === "GET" ? DEFAULT_READ_TIMEOUT_MS : DEFAULT_WRITE_TIMEOUT_MS);
  const controller = new AbortController();
  let timedOut = false;
  let timer: number | undefined;
  let removeAbortListener: (() => void) | undefined;
  if (timeout > 0) {
    timer = window.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeout);
  }
  if (init.signal) {
    const abort = () => controller.abort();
    if (init.signal.aborted) abort();
    else {
      init.signal.addEventListener("abort", abort, { once: true });
      removeAbortListener = () => init.signal?.removeEventListener("abort", abort);
    }
  }

  let response: Response;
  let raw: string;
  try {
    response = await fetch(path, { ...init, headers, signal: controller.signal });
    raw = await response.text();
  } catch (error) {
    if (timer !== undefined) window.clearTimeout(timer);
    removeAbortListener?.();
    if (timedOut) throw new APIError(0, "TIMEOUT", `Request ${path} timed out`);
    if (init.signal?.aborted) throw new APIError(0, "ABORTED", "Request was cancelled");
    throw new APIError(0, "NETWORK_ERROR", "Could not connect to NGFW API", error instanceof Error ? [error.message] : []);
  }

  if (timer !== undefined) window.clearTimeout(timer);
  removeAbortListener?.();
  let payload: APIEnvelope<T> | undefined;
  try {
    payload = raw ? (JSON.parse(raw) as APIEnvelope<T>) : undefined;
  } catch {
    throw new APIError(response.status, "INVALID_RESPONSE", "API returned an invalid response");
  }

  if (!response.ok || !payload?.success) {
    throw new APIError(
      response.status,
      payload?.error?.code ?? "REQUEST_FAILED",
      payload?.error?.message ?? `Request failed (${response.status})`,
      payload?.error?.details ?? [],
    );
  }
  return payload.data as T;
}

export function errorMessage(error: unknown): string {
  if (error instanceof APIError) {
    return error.details.length ? `${error.message}: ${error.details.join("; ")}` : error.message;
  }
  return error instanceof Error ? error.message : String(error);
}
