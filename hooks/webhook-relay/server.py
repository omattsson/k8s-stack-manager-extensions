#!/usr/bin/env python3
"""Webhook relay — forwards k8s-stack-manager events to arbitrary HTTP endpoints.

Supports multiple destination URLs, configurable event filtering, custom headers,
retry with exponential backoff, and a JSON-lines delivery log for debugging.

Inbound requests are accepted immediately and deliveries are processed by a
fixed-size worker pool, so thread count stays bounded under load.

Usage:
    export RELAY_WEBHOOK_SECRET="your-shared-secret"
    export RELAY_DESTINATIONS='[{"url":"https://monitoring.example/hook","events":["deploy-finalized"],"headers":{"X-Source":"stack-manager"}}]'
    python3 server.py
"""

import hashlib
import hmac
import json
import os
import queue
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
WORKER_COUNT = int(os.environ.get("RELAY_WORKER_COUNT", "8"))
QUEUE_SIZE = int(os.environ.get("RELAY_QUEUE_SIZE", "1000"))


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
_work_queue = queue.Queue(maxsize=QUEUE_SIZE)
_dropped = 0
_dropped_lock = threading.Lock()


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


def _worker():
    while True:
        item = _work_queue.get()
        if item is None:
            break
        dest, envelope, raw_body, request_id = item
        try:
            relay_to_destination(dest, envelope, raw_body, request_id)
        except Exception as exc:
            print(f"ERROR worker unhandled exception: {exc}", file=sys.stderr, flush=True)
        finally:
            _work_queue.task_done()


def dispatch(envelope: dict, raw_body: bytes, request_id: str) -> int:
    """Enqueue deliveries for matching destinations. Returns enqueued count."""
    global _dropped
    event = envelope.get("event", "")
    enqueued = 0
    for dest in DESTINATIONS:
        allowed_events = dest.get("events", [])
        if allowed_events and event not in allowed_events:
            continue
        try:
            _work_queue.put_nowait((dest, envelope, raw_body, request_id))
            enqueued += 1
        except queue.Full:
            with _dropped_lock:
                _dropped += 1
            print(
                f"WARN queue full, dropped dest={dest['name']} request_id={request_id}",
                file=sys.stderr,
                flush=True,
            )
    return enqueued


_workers: list[threading.Thread] = []


def start_workers(count: int = WORKER_COUNT) -> None:
    for _ in range(count):
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        _workers.append(t)


def stop_workers() -> None:
    for _ in _workers:
        _work_queue.put(None)
    for t in _workers:
        t.join(timeout=10)
    _workers.clear()


def get_queue_depth() -> int:
    return _work_queue.qsize()


def get_dropped_count() -> int:
    with _dropped_lock:
        return _dropped


class HookHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            body = {
                "status": "ok",
                "destinations": len(DESTINATIONS),
                "queue_depth": get_queue_depth(),
                "dropped": get_dropped_count(),
            }
            self.wfile.write(json.dumps(body).encode())
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
    print(
        f"INFO webhook-relay destinations={names} workers={WORKER_COUNT} queue_size={QUEUE_SIZE}",
        flush=True,
    )

    start_workers()

    host, _, port = LISTEN_ADDR.rpartition(":")
    port = int(port)
    httpd = ThreadingHTTPServer((host, port), HookHandler)
    print(f"INFO webhook-relay listening on {LISTEN_ADDR}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
        stop_workers()


if __name__ == "__main__":
    main()
