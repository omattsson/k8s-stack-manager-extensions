#!/usr/bin/env python3
"""Teams notifier — posts deploy results to Microsoft Teams via Incoming Webhook.

Subscribes to deploy-finalized events from k8s-stack-manager and sends
a formatted Adaptive Card message with instance details.

Usage:
    export TEAMS_WEBHOOK_URL="https://your-tenant.webhook.office.com/webhookb2/..."
    export TEAMS_WEBHOOK_SECRET="your-shared-secret"
    python3 server.py
"""

import hashlib
import hmac
import json
import os
import sys
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")
SECRET = os.environ.get("TEAMS_WEBHOOK_SECRET", "")
STACK_MANAGER_URL = os.environ.get("STACK_MANAGER_URL", "https://stack-manager.example")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", ":8080")


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


class HookHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
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
            post_to_teams(card)

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

    host, _, port = LISTEN_ADDR.rpartition(":")
    port = int(port)
    server = ThreadingHTTPServer((host, port), HookHandler)
    print(f"INFO teams-notifier listening on {LISTEN_ADDR}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
