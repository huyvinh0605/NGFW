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

export default defineConfig({
  plugins: [react()],
  customLogger: logger,
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/ws": { target: "http://127.0.0.1:8080", ws: true, changeOrigin: false },
    },
  },
});
