"""Lightweight, standard-library threaded HTTP mock server for integration testing."""

from __future__ import annotations

import gzip
import http.server
import threading
import time
from typing import Any


class MockHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler implementing test routes."""

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress standard logging during tests
        pass

    def do_GET(self) -> None:
        path = self.path

        if path == "/ok":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

        elif path == "/redir-out":
            self.send_response(302)
            self.send_header("Location", "http://evil.com/stolen")
            self.end_headers()

        elif path == "/redir-loop":
            self.send_response(302)
            self.send_header("Location", "/redir-loop")
            self.end_headers()

        elif path == "/429":
            self.send_response(429)
            self.send_header("Retry-After", "1")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Too Many Requests")

        elif path == "/503":
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Service Unavailable")

        elif path == "/slow":
            time.sleep(0.3)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Slow Response")

        elif path == "/big":
            payload = b"X" * 50_000
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        elif path == "/gzip-bomb":
            data = gzip.compress(b"BOMB" * 10_000)
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(data)

        elif path.startswith("/soft404"):
            html = b"<html><head><title>404 Not Found</title></head><body>Page not found.</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        else:
            self.send_response(404)
            self.end_headers()


class ThreadedMockServer:
    """Threaded HTTP server that runs locally on a dynamic port."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        class TimeoutHTTPServer(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                sock, addr = super().get_request()
                sock.settimeout(2.0)
                return sock, addr

        self.server = TimeoutHTTPServer((host, port), MockHandler)
        self.host, self.port = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
