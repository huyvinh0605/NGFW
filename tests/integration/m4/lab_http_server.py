#!/usr/bin/env python3
"""Temporary M4 acceptance origin; never run with production data."""

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="10.20.0.10")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def respond(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1 << 20:
                self.send_error(413)
                return
            self.rfile.read(length)
            marker = self.headers.get("X-M4-Marker", "")
            if not marker.isascii() or len(marker) > 128:
                self.send_error(400)
                return
            with lock, open(args.log, "a", encoding="utf-8") as log:
                log.write(json.dumps({"marker": marker, "method": self.command}) + "\n")
            body = marker.encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = respond
        do_POST = respond

        def log_message(self, *_):
            pass

    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
