import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { Agent, createServer, request } from "node:http";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import type { Socket } from "node:net";
import test, { type TestContext } from "node:test";
import { createServer as createViteServer, type ProxyOptions } from "vite";
import configure from "../vite.config.ts";

async function fixture(t: TestContext) {
  const root = await mkdtemp(join(tmpdir(), "ngfw-proxy-test-"));
  const sockets = new Set<Socket>();
  const received: Array<{ method: string; url: string; body: string; authorization?: string; port?: number }> = [];
  const upstream = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const record = { method: req.method!, url: req.url!, body: Buffer.concat(chunks).toString(), authorization: req.headers.authorization, port: req.socket.remotePort };
    received.push(record);
    if (req.url?.includes("parallel")) await new Promise((done) => setTimeout(done, 40));
    res.writeHead(req.headers.authorization === "Bearer fixture-token" ? 200 : 401, { "Content-Type": "application/json" });
    res.end(JSON.stringify(record));
  });
  upstream.keepAliveTimeout = 30_000;
  upstream.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const target = `http://127.0.0.1:${(upstream.address() as { port: number }).port}`;
  const config = await configure({ command: "serve", mode: "test" });
  const proxy = config.server!.proxy!;
  const api = proxy["/api"] as ProxyOptions;
  const vite = await createViteServer({
    ...config, configFile: false, root,
    // React is a plugin preset; this empty fixture only needs proxy lifecycle
    // hooks and must not run React dependency discovery in the temp directory.
    plugins: config.plugins?.filter((plugin) => !Array.isArray(plugin)),
    optimizeDeps: { noDiscovery: true, include: [] },
    server: { ...config.server, host: "127.0.0.1", port: 0, hmr: false,
      proxy: { "/api": { ...api, target }, "/ws": { ...proxy["/ws"] as ProxyOptions, target } } },
  });
  const browser = new Agent({ keepAlive: true, maxSockets: 64 });
  t.after(async () => {
    browser.destroy();
    await vite.close();
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((done) => upstream.close(() => done()));
    assert.equal(dirname(root), resolve(tmpdir()));
    assert.ok(basename(root).startsWith("ngfw-proxy-test-"));
    await rm(root, { recursive: true, force: true });
  });
  await vite.listen();
  const port = (vite.httpServer!.address() as { port: number }).port;
  function call(path: string, body?: string, authorization = "Bearer fixture-token") {
    return new Promise<{ status: number; connection?: string; clientPort?: number; record: typeof received[number] }>((done, reject) => {
      const req = request({ host: "127.0.0.1", port, path, agent: browser,
        method: body === undefined ? "GET" : "POST",
        headers: { Authorization: authorization, ...(body === undefined ? {} : { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }) },
      }, (res) => {
        const chunks: Buffer[] = [];
        const clientPort = res.socket.localPort;
        res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        res.on("end", () => {
          try { done({ status: res.statusCode!, connection: res.headers.connection, clientPort, record: JSON.parse(Buffer.concat(chunks).toString()) }); }
          catch (error) { reject(error); }
        });
      });
      req.on("error", reject);
      req.setTimeout(5000, () => req.destroy(new Error("fixture request timed out")));
      req.end(body);
    });
  }
  return { upstream, sockets, received, vite, port, call };
}

test("API proxy reuses both HTTP legs, preserves authentication, and releases its pool", async (t) => {
  const f = await fixture(t);
  const ports = new Set<number | undefined>();
  const browserPorts = new Set<number | undefined>();
  for (let i = 0; i < 20; i++) {
    const response = await f.call(`/api/v1/fixture?index=${i}`);
    assert.equal(response.status, 200);
    assert.notEqual(response.connection, "close");
    assert.equal(response.record.authorization, "Bearer fixture-token");
    assert.equal(response.record.url, `/api/v1/fixture?index=${i}`);
    ports.add(response.record.port);
    browserPorts.add(response.clientPort);
  }
  assert.equal(ports.size, 1, "sequential requests should reuse one upstream TCP connection");
  assert.equal(browserPorts.size, 1, "responses should also let the browser reuse its TCP connection");
  const denied = await f.call("/api/v1/fixture", undefined, "Bearer invalid-fixture-token");
  assert.equal(denied.status, 401, "pooling must not bypass upstream authentication");
  const closed = once([...f.sockets][0], "close");
  await f.vite.close();
  let deadline: ReturnType<typeof setTimeout>;
  try {
    await Promise.race([closed, new Promise((_, reject) => {
      deadline = setTimeout(() => reject(new Error("idle API pool survived server shutdown")), 1000);
    })]);
  } finally { clearTimeout(deadline!); }
  assert.equal(f.sockets.size, 0, "server shutdown must release idle upstream connections");
});

test("API pool bounds concurrent connections without mixing request bodies or responses", async (t) => {
  const f = await fixture(t);
  const responses = await Promise.all(Array.from({ length: 40 }, (_, i) => {
    const body = JSON.stringify({ index: i, value: `fixture-${i}` });
    return f.call(`/api/v1/parallel?index=${i}`, body).then((response) => {
      assert.equal(response.status, 200);
      assert.equal(response.record.method, "POST");
      assert.equal(response.record.body, body);
      assert.equal(response.record.url, `/api/v1/parallel?index=${i}`);
      return response;
    });
  }));
  const connectionCount = new Set(responses.map((response) => response.record.port)).size;
  assert.ok(connectionCount > 1, "pooling must preserve concurrent request handling");
  assert.ok(connectionCount <= 32, "concurrent requests must respect the pool bound");
  assert.equal(f.received.length, 40);
});

test("HTTP connections survive the UI polling interval on both proxy legs", async (t) => {
  const f = await fixture(t);
  const before = await f.call("/api/v1/fixture?poll=1");
  await new Promise((done) => setTimeout(done, 6000));
  const after = await f.call("/api/v1/fixture?poll=2");
  assert.equal(after.clientPort, before.clientPort, "the web server must keep idle HTTP alive beyond the 5s polling interval");
  assert.equal(after.record.port, before.record.port, "the API connection must also be reusable across polling cycles");
});

test("WebSocket upgrades retain authentication protocols and stay separate from the HTTP pool", async (t) => {
  const f = await fixture(t);
  await f.call("/api/v1/fixture");
  const httpPort = f.received[0].port;
  const protocols = "ngfw.v1, ngfw.auth.fixture";
  let upgradePort: number | undefined;
  let upgradeProtocols: string | undefined;
  const ping = Buffer.from([0x89, 0x80, 1, 2, 3, 4]);
  f.upstream.on("upgrade", (req, socket) => {
    upgradePort = req.socket.remotePort;
    upgradeProtocols = req.headers["sec-websocket-protocol"];
    const accept = createHash("sha1").update(String(req.headers["sec-websocket-key"]) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: ngfw.v1\r\n\r\n`);
    socket.once("data", (data) => {
      assert.deepEqual(data, ping);
      socket.write(Buffer.from([0x8a, 0x00]));
    });
  });
  const req = request({ host: "127.0.0.1", port: f.port, path: "/ws/events", agent: false,
    headers: { Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol": protocols },
  });
  req.end();
  const [, socket] = await once(req, "upgrade") as [unknown, Socket];
  t.after(() => socket.destroy());
  assert.notEqual(upgradePort, httpPort);
  assert.equal(upgradeProtocols, protocols);
  await f.call("/api/v1/fixture?after=upgrade");
  assert.equal(f.received[1].port, httpPort, "an upgrade must not consume the reusable HTTP connection");
  const pong = once(socket, "data");
  socket.write(ping);
  assert.deepEqual((await pong)[0], Buffer.from([0x8a, 0x00]));
  socket.destroy();
});
