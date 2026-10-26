import assert from "node:assert/strict";
import test from "node:test";
import { authenticatedSocketProtocols } from "../src/wsLifecycle";

test("WebSocket credentials survive header-safe encoding and empty token stays empty", () => {
  assert.deepEqual(authenticatedSocketProtocols(""), []);
  for (const token of ["static-token_ABC/+=", "credential with spaces", "mật-khẩu"]) {
    const protocols = authenticatedSocketProtocols(token);
    assert.equal(protocols[0], "ngfw.v1");
    assert.match(protocols[1], /^ngfw\.auth\.[A-Za-z0-9_-]+$/);
    const encoded = protocols[1].slice("ngfw.auth.".length);
    assert.equal(Buffer.from(encoded, "base64url").toString("utf8"), token);
  }
});
