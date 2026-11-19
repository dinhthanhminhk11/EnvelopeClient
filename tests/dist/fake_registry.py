"""Fake GitLab Generic Package Registry for tests/dist/test-dist.sh (loopback only, in memory).

    python3 -I tests/dist/fake_registry.py <token>

Prints the port on its first stdout line, then serves until killed:
  PUT  /api/v4/projects/<project>/packages/generic/<package>/<version>/<file>
       needs header JOB-TOKEN or PRIVATE-TOKEN equal to <token>; 201 {"message":"201 Created"}
  GET  same path: needs JOB-TOKEN, PRIVATE-TOKEN or Deploy-Token equal to <token> (401 otherwise); 404 when absent;
       else 302 to /blob/<n>?X-Amz-Signature=<n>, like gitlab.com redirecting to object storage; the package
       insecure-redirect always redirects to plain http on another host
  GET  /blob/<n>?...: the bytes (no credential needed)
  GET  /__log: JSON list of every request: method, path, which credential headers were sent and whether they were
       correct (never their values), and the User-Agent (a ~/.curlrc the tools must not read can set it)
  POST /__tamper/<file>: replaces the stored file's last byte (tests the SHA-256 check of fetch-core.sh)
"""

import http.server
import json
import re
import sys
import threading

TOKEN = sys.argv[1]
AUTH_HEADERS = ("JOB-TOKEN", "PRIVATE-TOKEN", "Deploy-Token", "Authorization")
PACKAGE_PATH = re.compile(r"^/api/v4/projects/([^/]+)/packages/generic/([^/]+)/([^/]+)/([^/?]+)$")
files = {}
blobs = []
log = []
lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def record(self):
        sent = {name: self.headers.get(name) == TOKEN for name in AUTH_HEADERS if self.headers.get(name) is not None}
        with lock:
            log.append({"method": self.command, "path": self.path.split("?")[0], "auth": sent,
                        "ua": self.headers.get("User-Agent", "")})
        return sent

    def reply(self, code, body=b"", headers=()):
        self.send_response(code)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorised(self, sent, allowed):
        return any(sent.get(name) for name in allowed)

    def do_PUT(self):
        sent = self.record()
        match = PACKAGE_PATH.match(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if not match:
            return self.reply(404)
        if not self.authorised(sent, ("JOB-TOKEN", "PRIVATE-TOKEN")):
            return self.reply(401, b'{"message":"401 Unauthorized"}')
        with lock:
            files[match.groups()] = body
        self.reply(201, b'{"message":"201 Created"}', [("Content-Type", "application/json")])

    def do_GET(self):
        sent = self.record()
        if self.path == "/__log":
            with lock:
                body = json.dumps(log).encode()
            return self.reply(200, body, [("Content-Type", "application/json")])
        blob = re.match(r"^/blob/([0-9]+)\?X-Amz-Signature=[0-9]+$", self.path)
        if blob:
            with lock:
                index = int(blob.group(1))
                data = blobs[index] if index < len(blobs) else None
            return self.reply(200, data) if data is not None else self.reply(404)
        match = PACKAGE_PATH.match(self.path)
        if not match:
            return self.reply(404)
        if not self.authorised(sent, ("JOB-TOKEN", "PRIVATE-TOKEN", "Deploy-Token")):
            return self.reply(401, b'{"message":"401 Unauthorized"}')
        if match.group(2) == "insecure-redirect":
            return self.reply(302, b"", [("Location", "http://example.invalid/blob/0?X-Amz-Signature=0")])
        with lock:
            data = files.get(match.groups())
            if data is None:
                return self.reply(404, b'{"message":"404 Not Found"}')
            blobs.append(data)
            index = len(blobs) - 1
        host = f"127.0.0.1:{self.server.server_address[1]}"
        self.reply(302, b"", [("Location", f"http://{host}/blob/{index}?X-Amz-Signature={index}")])

    def do_POST(self):
        self.record()
        tamper = re.match(r"^/__tamper/([^/]+)$", self.path)
        if not tamper:
            return self.reply(404)
        with lock:
            for key in files:
                if key[3] == tamper.group(1):
                    files[key] = files[key][:-1] + bytes([files[key][-1] ^ 1])
                    return self.reply(200)
        self.reply(404)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(server.server_address[1], flush=True)
server.serve_forever()
