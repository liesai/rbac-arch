#!/usr/bin/env python3
import http.server
import socketserver
from pathlib import Path

PORT = 8012
DIRECTORY = Path(__file__).parent / "dist"
DIRECTORY.mkdir(parents=True, exist_ok=True)

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIRECTORY), **kwargs)

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving dashboard dist at http://0.0.0.0:{PORT}")
        httpd.serve_forever()
