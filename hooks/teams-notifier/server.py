#!/usr/bin/env python3
"""Teams notifier — posts deploy results to Microsoft Teams via Incoming Webhook.

Subscribes to deploy-finalized events from k8s-stack-manager and sends
a formatted Adaptive Card message with instance details.

Inbound requests are accepted immediately and Teams posts are processed by a
fixed-size worker pool, so thread count stays bounded under load.

Usage:
    export TEAMS_WEBHOOK_URL="https://your-tenant.webhook.office.com/webhookb2/..."
    export TEAMS_WEBHOOK_SECRET="your-shared-secret"
    python3 server.py
"""

import hashlib
import hmac
import json
import os
import queue
import sys
import urllib.request
import urllib.error
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")
SECRET = os.environ.get("TEAMS_WEBHOOK_SECRET", "")
STACK_MANAGER_URL = os.environ.get("STACK_MANAGER_URL", "https://stack-manager.example")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", ":8080")
WORKER_COUNT = int(os.environ.get("TEAMS_WORKER_COUNT", "4"))
QUEUE_SIZE = int(os.environ.get("TEAMS_QUEUE_SIZE", "500"))

_work_queue = queue.Queue(maxsize=QUEUE_SIZE)
_dropped = 0
_dropped_lock = threading.Lock()


def verify_signature(body: bytes, signature: str) -> bool:
    if not SECRET:
        return True
    expected = "sha256=" + hmac.new(
        SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def build_adaptive_card(envelope: dict) -> dict:
    instance = envelope.get("instance", {})
    name = instance.get("name", "unknown")
    namespace = instance.get("namespace", "unknown")
    branch = instance.get("branch", "unknown")
    cluster_id = instance.get("cluster_id", "")
    status = instance.get("status", "")
    instance_id = instance.get("id", "")

    is_success = status in ("deployed", "running")
    emoji = "\u2705" if is_success else "\u274C"
    outcome = "succeeded" if is_success else "failed"
    color = "good" if is_success else "attention"

    instance_url = f"{STACK_MANAGER_URL}/stack-instances/{instance_id}"

    facts = [
        {"title": "Namespace", "value": namespace},
        {"title": "Branch", "value": branch},
    ]
    if cluster_id:
        facts.append({"title": "Cluster", "value": cluster_id})

    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "medium",
                            "weight": "bolder",
                            "text": f"{emoji} Deploy {outcome} \u2014 {name}",
                            "style": "heading",
                            "color": color,
                        },
                        {
                            "type": "FactSet",
                            "facts": facts,
                        },
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "View instance",
                            "url": instance_url,
                        }
                    ],
                },
            }
        ],
    }

    return card


def post_to_teams(payload: dict) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        TEAMS_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            _ = resp.read()
    except urllib.error.URLError as exc:
        print(f"WARN teams post failed: {exc}", file=sys.stderr, flush=True)


def _worker():
    while True:
        item = _work_queue.get()
        if item is None:
            break
        try:
            post_to_teams(item)
        except Exception as exc:
            print(f"ERROR worker unhandled exception: {exc}", file=sys.stderr, flush=True)
        finally:
            _work_queue.task_done()


def enqueue_card(card: dict) -> bool:
    """Enqueue a card for async delivery. Returns False if queue is full."""
    global _dropped
    try:
        _work_queue.put_nowait(card)
        return True
    except queue.Full:
        with _dropped_lock:
            _dropped += 1
        print("WARN queue full, dropped teams notification", file=sys.stderr, flush=True)
        return False


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

        if event == "deploy-finalized" and TEAMS_WEBHOOK_URL:
            card = build_adaptive_card(envelope)
            enqueue_card(card)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"allowed":true}')

    def log_message(self, format, *args):
        print(f"INFO {args[0]}", flush=True)


def main():
    if not TEAMS_WEBHOOK_URL:
        print("FATAL TEAMS_WEBHOOK_URL is required", file=sys.stderr, flush=True)
        sys.exit(1)
    if not SECRET:
        print("WARN TEAMS_WEBHOOK_SECRET not set -- signature verification disabled", file=sys.stderr, flush=True)

    print(
        f"INFO teams-notifier workers={WORKER_COUNT} queue_size={QUEUE_SIZE}",
        flush=True,
    )

    start_workers()

    host, _, port = LISTEN_ADDR.rpartition(":")
    port = int(port)
    httpd = ThreadingHTTPServer((host, port), HookHandler)
    print(f"INFO teams-notifier listening on {LISTEN_ADDR}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
        stop_workers()


if __name__ == "__main__":
    main()
