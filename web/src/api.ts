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

export function storedToken(): string {
  return window.localStorage.getItem(TOKEN_KEY) ?? "";
}

export function persistToken(token: string): void {
  if (token) window.localStorage.setItem(TOKEN_KEY, token);
  else window.localStorage.removeItem(TOKEN_KEY);
}

export async function api<T>(path: string, init: RequestInit = {}, token = storedToken()): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body != null && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  let response: Response;
  try {
    response = await fetch(path, { ...init, headers });
  } catch {
    throw new APIError(0, "NETWORK_ERROR", "Không kết nối được tới NGFW API");
  }

  const raw = await response.text();
  let payload: APIEnvelope<T> | undefined;
  try {
    payload = raw ? (JSON.parse(raw) as APIEnvelope<T>) : undefined;
  } catch {
    throw new APIError(response.status, "INVALID_RESPONSE", "API trả về dữ liệu không hợp lệ");
  }

  if (!response.ok || !payload?.success) {
    throw new APIError(
      response.status,
      payload?.error?.code ?? "REQUEST_FAILED",
      payload?.error?.message ?? `Yêu cầu thất bại (${response.status})`,
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

