#!/usr/bin/env python3
"""Slack notifier — posts deploy results to a Slack channel via Incoming Webhook.

Subscribes to deploy-finalized events from k8s-stack-manager and sends
a formatted Slack Block Kit message with instance details.

Usage:
    export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxx"
    export SLACK_WEBHOOK_SECRET="your-shared-secret"
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

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SECRET = os.environ.get("SLACK_WEBHOOK_SECRET", "")
STACK_MANAGER_URL = os.environ.get("STACK_MANAGER_URL", "https://stack-manager.example")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", ":8080")


def verify_signature(body: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature from X-StackManager-Signature header."""
    if not SECRET:
        return True  # No secret configured — skip verification
    expected = "sha256=" + hmac.new(
        SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def build_slack_blocks(envelope: dict) -> dict:
    """Build a Slack Block Kit message from an EventEnvelope."""
    instance = envelope.get("instance", {})
    name = instance.get("name", "unknown")
    namespace = instance.get("namespace", "unknown")
    branch = instance.get("branch", "unknown")
    cluster_id = instance.get("cluster_id", "")
    status = instance.get("status", "")
    instance_id = instance.get("id", "")

    # Determine success/failure from instance status
    is_success = status in ("deployed", "running")
    emoji = "✅" if is_success else "❌"
    outcome = "succeeded" if is_success else "failed"

    instance_url = f"{STACK_MANAGER_URL}/stack-instances/{instance_id}"

    cluster_text = f" · Cluster: `{cluster_id}`" if cluster_id else ""

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *Deploy {outcome}* — `{name}` on `{branch}`\n"
                    f"Namespace: `{namespace}`{cluster_text}\n"
                    f"<{instance_url}|View instance →>"
                ),
            },
        },
    ]

    return {"blocks": blocks}


def post_to_slack(payload: dict) -> None:
    """Post a message to Slack via Incoming Webhook."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            _ = resp.read()
    except urllib.error.URLError as exc:
        print(f"WARN slack post failed: {exc}", file=sys.stderr, flush=True)


class HookHandler(BaseHTTPRequestHandler):
    """HTTP handler for k8s-stack-manager webhook events."""

    def do_GET(self):
        """Health check endpoint."""
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        """Handle incoming event hook."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Verify HMAC signature
        signature = self.headers.get("X-StackManager-Signature", "")
        if not verify_signature(body, signature):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"invalid signature"}')
            return

        # Parse envelope
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

        # Post to Slack for deploy-finalized events
        if event == "deploy-finalized" and SLACK_WEBHOOK_URL:
            slack_payload = build_slack_blocks(envelope)
            post_to_slack(slack_payload)

        # Always return allowed (post-* events are fire-and-forget)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"allowed":true}')

    def log_message(self, format, *args):
        """Structured log output."""
        print(f"INFO {args[0]}", flush=True)


def main():
    if not SLACK_WEBHOOK_URL:
        print("FATAL SLACK_WEBHOOK_URL is required", file=sys.stderr, flush=True)
        sys.exit(1)

    host, _, port = LISTEN_ADDR.rpartition(":")
    port = int(port)
    server = ThreadingHTTPServer((host, port), HookHandler)
    print(f"INFO slack-notifier listening on {LISTEN_ADDR}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
