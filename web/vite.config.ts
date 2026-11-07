import { Agent, type Server } from "node:http";
import { createLogger, defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { isExpectedWebSocketProxyTeardown } from "./src/wsLifecycle";

const logger = createLogger();
const reportError = logger.error.bind(logger);
logger.error = (message, options) => {
  // Vite attaches this listener to the browser-facing half of a proxied
  // WebSocket. EPIPE/ECONNRESET here means the browser left during teardown;
  // upstream API and handshake failures continue to be reported normally.
  if (message.includes("ws proxy socket error") && isExpectedWebSocketProxyTeardown(message)) return;
  reportError(message, options);
};

export default defineConfig(() => {
  // The proxy's default agent=false forces Connection: close on every API
  // request. Reuse a bounded pool instead; leave request timeouts to api.ts
  // so long-running config operations are not cut short by a socket timeout.
  const apiAgent = new Agent({
    keepAlive: true,
    maxSockets: 32,
    maxTotalSockets: 32,
    // Retain a complete polling batch (currently 11 parallel API reads).
    maxFreeSockets: 16,
    scheduling: "lifo",
  });
  const configureConnections = (server: Server | null) => {
    if (!server) return;
    // Node's 5s idle default races the UI's 5s polling interval. This only
    // affects idle HTTP connections, not the duration of an active request.
    server.keepAliveTimeout = 30_000;
    server.once("close", () => apiAgent.destroy());
  };

  return {
    plugins: [react(), {
      name: "ngfw-api-connection-pool",
      configureServer(server) {
        configureConnections(server.httpServer);
      },
      configurePreviewServer(server) {
        configureConnections(server.httpServer);
      },
    }],
    customLogger: logger,
    server: {
      port: 5173,
      proxy: {
        "/api": { target: "http://127.0.0.1:8080", agent: apiAgent },
        // Upgraded, long-lived sockets must not occupy the HTTP request pool.
        "/ws": { target: "http://127.0.0.1:8080", ws: true, changeOrigin: false },
      },
    },
  };
});
