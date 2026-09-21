/** Minimal WebSocket shape used by the cleanup path and its tests. */
export type SocketLike = {
  readyState: number;
  close: (code?: number, reason?: string) => void;
  addEventListener: (type: "open", listener: () => void, options?: { once?: boolean }) => void;
};

export const SOCKET_CONNECTING = 0;
export const SOCKET_OPEN = 1;

export function reconnectDelay(attempt: number, baseMillis = 1000, maximumMillis = 30000): number {
  const exponent = Math.max(0, Math.min(10, Math.floor(attempt)));
  return Math.min(maximumMillis, baseMillis * (2 ** exponent));
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
