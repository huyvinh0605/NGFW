import assert from "node:assert/strict";
import test from "node:test";
import { closeSocketAfterOpen, INITIAL_WEBSOCKET_DIAL_DELAY_MS, isExpectedWebSocketProxyTeardown, reconnectDelay, type SocketLike } from "../src/wsLifecycle.ts";

test("delays the initial dial long enough for the StrictMode effect probe", () => {
  assert.ok(INITIAL_WEBSOCKET_DIAL_DELAY_MS >= 100, "a zero-delay dial can race StrictMode cleanup and create a proxy EPIPE");
});

test("recognizes only expected browser-side proxy teardown errors", () => {
  assert.equal(isExpectedWebSocketProxyTeardown("ws proxy socket error: Error: write EPIPE"), true);
  assert.equal(isExpectedWebSocketProxyTeardown({ code: "ECONNRESET" }), true);
  assert.equal(isExpectedWebSocketProxyTeardown("ws proxy error: 502 upstream unavailable"), false);
  assert.equal(isExpectedWebSocketProxyTeardown({ code: "ECONNREFUSED" }), false);
});

test("does not abort a CONNECTING socket during component cleanup", () => {
  let openListener: (() => void) | undefined;
  const closes: Array<[number | undefined, string | undefined]> = [];
  const socket: SocketLike = {
    readyState: 0,
    close: (code, reason) => closes.push([code, reason]),
    addEventListener: (_type, listener) => { openListener = listener; },
  };

  closeSocketAfterOpen(socket);
  assert.deepEqual(closes, []);
  assert.ok(openListener);

  socket.readyState = 1;
  openListener?.();
  assert.deepEqual(closes, [[1000, "component unmounted"]]);
});

test("closes an already open socket with a normal close code", () => {
  const closes: Array<[number | undefined, string | undefined]> = [];
  const socket: SocketLike = {
    readyState: 1,
    close: (code, reason) => closes.push([code, reason]),
    addEventListener: () => undefined,
  };

  closeSocketAfterOpen(socket);
  assert.deepEqual(closes, [[1000, "component unmounted"]]);
});

test("uses bounded exponential delay for reconnects", () => {
  assert.equal(reconnectDelay(0), 1000);
  assert.equal(reconnectDelay(1), 2000);
  assert.equal(reconnectDelay(5), 30000);
  assert.equal(reconnectDelay(50), 30000);
});
