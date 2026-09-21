import assert from "node:assert/strict";
import test from "node:test";
import { closeSocketAfterOpen, type SocketLike } from "../src/wsLifecycle.ts";

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
