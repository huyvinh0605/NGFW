/** Minimal WebSocket shape used by the cleanup path and its tests. */
export type SocketLike = {
  readyState: number;
  close: (code?: number, reason?: string) => void;
  addEventListener: (type: "open", listener: () => void, options?: { once?: boolean }) => void;
};

export const SOCKET_CONNECTING = 0;
export const SOCKET_OPEN = 1;

// React StrictMode deliberately mounts, cleans up, and mounts effects once in
// development. Waiting briefly before the first dial lets that probe finish
// without opening a WebSocket which would immediately be closed again.
export const INITIAL_WEBSOCKET_DIAL_DELAY_MS = 150;

export function reconnectDelay(attempt: number, baseMillis = 1000, maximumMillis = 30000): number {
  const exponent = Math.max(0, Math.min(10, Math.floor(attempt)));
  return Math.min(maximumMillis, baseMillis * (2 ** exponent));
}

// Vite emits this from its browser-facing proxy socket after the browser has
// already gone away (for example during a refresh). It is distinct from an
// upstream API error and is safe to silence only in that narrow proxy log.
export function isExpectedWebSocketProxyTeardown(value: unknown): boolean {
  if (typeof value === "string") return /\b(?:EPIPE|ECONNRESET)\b/.test(value);
  if (typeof value === "object" && value !== null && "code" in value) {
    const code = (value as { code?: unknown }).code;
    return code === "EPIPE" || code === "ECONNRESET";
  }
  return false;
}

/**
 * Close a socket owned by a component without aborting an in-flight handshake.
 * Browsers report a noisy "closed before connection was established" error
 * when close() is called while CONNECTING. Waiting for OPEN also gives the
 * server a normal close frame and prevents the Vite proxy from seeing EPIPE.
 */
export function closeSocketAfterOpen(socket: SocketLike, reason = "component unmounted"): void {
  if (socket.readyState === SOCKET_OPEN) {
    socket.close(1000, reason);
    return;
  }
  if (socket.readyState === SOCKET_CONNECTING) {
    socket.addEventListener("open", () => {
      if (socket.readyState === SOCKET_OPEN) socket.close(1000, reason);
    }, { once: true });
  }
}
