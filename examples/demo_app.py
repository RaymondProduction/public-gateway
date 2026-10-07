#!/usr/bin/env python3
"""Harmless HTTP test app: never serves local files or accepts uploads."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}\n'
            kind = "application/json"
        else:
            body = ("Public Gateway працює!\n"
                    "Цю відповідь сформувала програма на твоєму пристрої, а не на VPS.\n").encode()
            kind = "text/plain; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="VPN IPv4 of this device, e.g. 10.77.0.2")
    parser.add_argument("--port", type=int, default=3000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")
    print(f"Demo on {args.bind}:{args.port}; Ctrl+C stops it.", flush=True)
    try:
        ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
