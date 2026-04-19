#!/usr/bin/env python3
"""Teams notifier — posts deploy results to a Microsoft Teams webhook.

Subscribes to post-deploy events from k8s-stack-manager with failure_policy=ignore.
Posts a summary message to a configured Teams webhook URL.

Usage:
    export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."
    export GATE_WEBHOOK_SECRET="your-shared-secret"
    python3 server.py
"""

import hmac
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("GATE_WEBHOOK_SECRET", "")
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")


def verify_signature(body: bytes, signature: str) -> bool:
    if not SECRET:
        return True
    expected = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def post_to_teams(message: str):
    import requests
    payload = {"text": message}
    resp = requests.post(TEAMS_WEBHOOK_URL, json=payload)
    resp.raise_for_status()


class TeamsNotifierHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        signature = self.headers.get("X-StackManager-Signature", "")
        if not verify_signature(body, signature):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"invalid signature"}')
            return
        try:
            envelope = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"invalid json"}')
            return
        # Compose message
        instance = envelope.get("instance", {})
        status = envelope.get("status", "unknown")
        message = f"Deploy result: {status}\nInstance: {instance.get('name', '?')} ({instance.get('namespace', '?')})"
        try:
            post_to_teams(message)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'{{"error":"teams post failed: {e}"}}'.encode())
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, format, *args):
        pass


def main():
    if not TEAMS_WEBHOOK_URL:
        print("ERROR: TEAMS_WEBHOOK_URL not set", flush=True)
        exit(1)
    server = ThreadingHTTPServer(("", 8080), TeamsNotifierHandler)
    print("Teams notifier listening on :8080", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
