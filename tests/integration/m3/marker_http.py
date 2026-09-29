#!/usr/bin/env python3
"""Bounded HTTP marker fixture for the isolated M3 acceptance lab.

The server records one JSON line per request before replying. The client uses a
unique NGFW_M3_TEST_<nonce> marker, so an acceptance assertion can distinguish
"packet reached the DMZ application" from an unrelated health-check request.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MARKER = re.compile(rb"NGFW_M3_TEST_[A-Za-z0-9_.-]{1,128}")


def append_record(path: Path, record: dict[str, object]) -> None:
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def serve(args: argparse.Namespace) -> int:
    log_path = Path(args.log).resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    max_body = args.max_body

    class Handler(BaseHTTPRequestHandler):
        server_version = "NGFWM3Fixture/1"

        def log_message(self, _format: str, *_values: object) -> None:
            return

        def handle_request(self) -> None:
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError:
                self.send_error(400, "invalid content length")
                return
            if length < 0 or length > max_body:
                self.send_error(413, "request body exceeds fixture limit")
                return
            body = self.rfile.read(length) if length else b""
            marker_input = self.path.encode() + b"\n" + self.headers.get("X-NGFW-Marker", "").encode() + b"\n" + body
            match = MARKER.search(marker_input)
            marker = match.group(0).decode() if match else ""
            record = {
                "timestamp": time.time_ns(),
                "client": self.client_address[0],
                "method": self.command,
                "path": self.path[:2048],
                "marker": marker,
                "body_bytes": len(body),
            }
            append_record(log_path, record)
            payload = json.dumps({"received": True, "marker": marker}, sort_keys=True).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = handle_request
        do_POST = handle_request

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.daemon_threads = True
    if args.ready_file:
        ready = Path(args.ready_file).resolve()
        ready.parent.mkdir(parents=True, exist_ok=True)
        ready.write_text(json.dumps({"bind": args.bind, "port": server.server_port}) + "\n", encoding="utf-8")
    print(json.dumps({"status": "LISTENING", "bind": args.bind, "port": server.server_port, "log": str(log_path)}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def send(args: argparse.Namespace) -> int:
    marker = f"NGFW_M3_TEST_{args.nonce}"
    body = marker.encode() if args.method == "POST" else None
    request = urllib.request.Request(args.url, data=body, method=args.method, headers={"X-NGFW-Marker": marker, "Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            payload = response.read(65537)
            if len(payload) > 65536:
                raise RuntimeError("response exceeds 64 KiB")
            status = response.status
    except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
        print(json.dumps({"marker": marker, "delivered": False, "error": str(error)}))
        return 0 if args.expect_failure else 1
    print(json.dumps({"marker": marker, "delivered": True, "status": status, "body": payload.decode(errors="replace")}))
    if args.expect_failure:
        return 1
    return 0 if status == args.expect_status else 1


def count(args: argparse.Namespace) -> int:
    marker = f"NGFW_M3_TEST_{args.nonce}"
    total = 0
    path = Path(args.log)
    if path.exists():
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    if json.loads(line).get("marker") == marker:
                        total += 1
                except (json.JSONDecodeError, AttributeError):
                    continue
    print(json.dumps({"marker": marker, "count": total, "expected": args.expected}))
    return 0 if total == args.expected else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    server = commands.add_parser("serve")
    server.add_argument("--bind", default="0.0.0.0")
    server.add_argument("--port", type=int, default=18080)
    server.add_argument("--log", required=True)
    server.add_argument("--ready-file")
    server.add_argument("--max-body", type=int, default=65536)
    server.set_defaults(handler=serve)
    client = commands.add_parser("send")
    client.add_argument("--url", required=True)
    client.add_argument("--nonce", required=True)
    client.add_argument("--method", choices=("GET", "POST"), default="POST")
    client.add_argument("--timeout", type=float, default=3.0)
    client.add_argument("--expect-status", type=int, default=200)
    client.add_argument("--expect-failure", action="store_true")
    client.set_defaults(handler=send)
    counter = commands.add_parser("count")
    counter.add_argument("--log", required=True)
    counter.add_argument("--nonce", required=True)
    counter.add_argument("--expected", type=int, required=True)
    counter.set_defaults(handler=count)
    return root


def main() -> int:
    args = parser().parse_args()
    if getattr(args, "max_body", 1) < 1 or getattr(args, "max_body", 1) > 1 << 20:
        raise SystemExit("--max-body must be between 1 and 1048576")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", getattr(args, "nonce", "valid")):
        raise SystemExit("--nonce must contain 1..128 safe characters")
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
