#!/usr/bin/env python3
"""Webhook relay — forwards k8s-stack-manager events to arbitrary HTTP endpoints.

Supports multiple destination URLs, configurable event filtering, custom headers,
retry with exponential backoff, and a JSON-lines delivery log for debugging.

Usage:
    export RELAY_WEBHOOK_SECRET="your-shared-secret"
    export RELAY_DESTINATIONS='[{"url":"https://monitoring.example/hook","events":["deploy-finalized"],"headers":{"X-Source":"stack-manager"}}]'
    python3 server.py
"""

import hashlib
import hmac
import json
import os
import sys
import time
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("RELAY_WEBHOOK_SECRET", "")
DESTINATIONS_JSON = os.environ.get("RELAY_DESTINATIONS", "[]")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", ":8080")
LOG_FILE = os.environ.get("RELAY_LOG_FILE", "")
MAX_RETRIES = int(os.environ.get("RELAY_MAX_RETRIES", "3"))
INITIAL_BACKOFF = float(os.environ.get("RELAY_INITIAL_BACKOFF", "1.0"))
REQUEST_TIMEOUT = int(os.environ.get("RELAY_REQUEST_TIMEOUT", "5"))


def load_destinations():
    try:
        dests = json.loads(DESTINATIONS_JSON)
    except json.JSONDecodeError:
        print("FATAL RELAY_DESTINATIONS is not valid JSON", file=sys.stderr, flush=True)
        sys.exit(1)
    for i, d in enumerate(dests):
        if "url" not in d:
            print(f"FATAL destination[{i}] missing 'url'", file=sys.stderr, flush=True)
            sys.exit(1)
        d.setdefault("events", [])
        d.setdefault("headers", {})
        d.setdefault("name", f"dest-{i}")
    return dests


DESTINATIONS = load_destinations()

_log_lock = threading.Lock()


def log_delivery(entry: dict) -> None:
    if not LOG_FILE:
        return
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    with _log_lock:
        try:
            with open(LOG_FILE, "a") as f:
                f.write(line)
        except OSError as exc:
            print(f"WARN log write failed: {exc}", file=sys.stderr, flush=True)


def verify_signature(body: bytes, signature: str) -> bool:
    if not SECRET:
        return True
    expected = "sha256=" + hmac.new(
        SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def relay_to_destination(dest: dict, envelope: dict, raw_body: bytes, request_id: str) -> None:
    url = dest["url"]
    name = dest["name"]
    headers = {"Content-Type": "application/json"}
    headers.update(dest.get("headers", {}))

    attempt = 0
    backoff = INITIAL_BACKOFF
    last_error = ""
    status_code = 0

    while attempt < MAX_RETRIES:
        attempt += 1
        try:
            req = urllib.request.Request(url, data=raw_body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                status_code = resp.status
                _ = resp.read()

            print(
                f"INFO relay dest={name} request_id={request_id} attempt={attempt} status={status_code}",
                flush=True,
            )
            log_delivery({
                "ts": time.time(),
                "dest": name,
                "url": url,
                "request_id": request_id,
                "event": envelope.get("event", ""),
                "attempt": attempt,
                "status": status_code,
                "ok": True,
            })
            return

        except urllib.error.HTTPError as exc:
            status_code = exc.code
            last_error = f"HTTP {exc.code}"
        except urllib.error.URLError as exc:
            last_error = str(exc.reason)
        except OSError as exc:
            last_error = str(exc)

        print(
            f"WARN relay dest={name} request_id={request_id} attempt={attempt}/{MAX_RETRIES} error={last_error}",
            file=sys.stderr,
            flush=True,
        )

        if attempt < MAX_RETRIES:
            time.sleep(backoff)
            backoff *= 2

    print(
        f"ERROR relay dest={name} request_id={request_id} exhausted retries error={last_error}",
        file=sys.stderr,
        flush=True,
    )
    log_delivery({
        "ts": time.time(),
        "dest": name,
        "url": url,
        "request_id": request_id,
        "event": envelope.get("event", ""),
        "attempt": attempt,
        "status": status_code,
        "ok": False,
        "error": last_error,
    })


def dispatch(envelope: dict, raw_body: bytes, request_id: str) -> None:
    event = envelope.get("event", "")
    threads = []
    for dest in DESTINATIONS:
        allowed_events = dest.get("events", [])
        if allowed_events and event not in allowed_events:
            continue
        t = threading.Thread(
            target=relay_to_destination,
            args=(dest, envelope, raw_body, request_id),
            daemon=True,
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=MAX_RETRIES * REQUEST_TIMEOUT + 30)


class HookHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            dest_count = len(DESTINATIONS)
            self.wfile.write(json.dumps({"status": "ok", "destinations": dest_count}).encode())
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

        event = envelope.get("event", "")
        instance = envelope.get("instance", {})
        request_id = envelope.get("request_id", "")
        print(
            f"INFO event={event} instance={instance.get('name', '?')} request_id={request_id}",
            flush=True,
        )

        dispatch(envelope, body, request_id)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"allowed":true}')

    def log_message(self, format, *args):
        print(f"INFO {args[0]}", flush=True)


def main():
    if not DESTINATIONS:
        print("FATAL RELAY_DESTINATIONS is empty", file=sys.stderr, flush=True)
        sys.exit(1)

    names = [d["name"] for d in DESTINATIONS]
    print(f"INFO webhook-relay destinations={names}", flush=True)

    host, _, port = LISTEN_ADDR.rpartition(":")
    port = int(port)
    server = ThreadingHTTPServer((host, port), HookHandler)
    print(f"INFO webhook-relay listening on {LISTEN_ADDR}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
