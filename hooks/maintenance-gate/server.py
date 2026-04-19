#!/usr/bin/env python3
"""Maintenance gate — blocks deploys outside configurable business hours.

Subscribes to pre-deploy events from k8s-stack-manager with failure_policy=fail.
Returns {"allowed": false} when the current time is outside the permitted window.

Usage:
    export GATE_WEBHOOK_SECRET="your-shared-secret"
    python3 server.py
"""

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

SECRET = os.environ.get("GATE_WEBHOOK_SECRET", "")
ALLOWED_DAYS = os.environ.get("ALLOWED_DAYS", "mon,tue,wed,thu,fri").lower().split(",")
ALLOWED_START_HOUR = int(os.environ.get("ALLOWED_START_HOUR", "8"))
ALLOWED_END_HOUR = int(os.environ.get("ALLOWED_END_HOUR", "17"))
TZ_NAME = os.environ.get("TIMEZONE", "Europe/Stockholm")
BYPASS_HEADER = os.environ.get("BYPASS_HEADER", "")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", ":8080")

TZ = ZoneInfo(TZ_NAME)

DAY_ABBREVS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def verify_signature(body: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature from X-StackManager-Signature header."""
    if not SECRET:
        return True
    expected = "sha256=" + hmac.new(
        SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def is_deploy_allowed() -> tuple[bool, str]:
    """Check if the current time is within the allowed deploy window."""
    now = datetime.now(TZ)
    day = DAY_ABBREVS[now.weekday()]
    hour = now.hour

    if day not in ALLOWED_DAYS or hour < ALLOWED_START_HOUR or hour >= ALLOWED_END_HOUR:
        days_str = "-".join([ALLOWED_DAYS[0], ALLOWED_DAYS[-1]]) if len(ALLOWED_DAYS) > 1 else ALLOWED_DAYS[0]
        return False, (
            f"Deploys blocked: outside business hours "
            f"({day} {hour:02d}:00 {TZ_NAME}, "
            f"allowed {days_str} {ALLOWED_START_HOUR:02d}:00-{ALLOWED_END_HOUR:02d}:00)"
        )

    return True, ""


class GateHandler(BaseHTTPRequestHandler):
    """HTTP handler for maintenance gate webhook."""

    def do_GET(self):
        """Health check + status endpoint."""
        if self.path == "/healthz":
            allowed, msg = is_deploy_allowed()
            status_info = {"status": "ok", "deploys_allowed": allowed}
            if msg:
                status_info["reason"] = msg
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(status_info).encode())
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        """Handle pre-deploy gate check."""
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

        request_id = envelope.get("request_id", "")
        instance = envelope.get("instance", {})

        # Check for bypass header
        if BYPASS_HEADER and self.headers.get("X-Bypass-Gate", "") == BYPASS_HEADER:
            print(
                f"INFO gate=bypassed instance={instance.get('name', '?')} request_id={request_id}",
                flush=True,
            )
            self._respond(200, {"allowed": True, "message": "bypass header accepted"})
            return

        # Check deploy window
        allowed, message = is_deploy_allowed()
        print(
            f"INFO gate={'open' if allowed else 'closed'} instance={instance.get('name', '?')} request_id={request_id}",
            flush=True,
        )

        response = {"allowed": allowed}
        if message:
            response["message"] = message

        self._respond(200, response)

    def _respond(self, status: int, body: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        print(f"INFO {args[0]}", flush=True)


def main():
    if not SECRET:
        print("WARN GATE_WEBHOOK_SECRET not set — signature verification disabled", file=sys.stderr, flush=True)

    print(
        f"INFO maintenance-gate starting schedule={','.join(ALLOWED_DAYS)} "
        f"hours={ALLOWED_START_HOUR:02d}-{ALLOWED_END_HOUR:02d} tz={TZ_NAME}",
        flush=True,
    )

    host, _, port = LISTEN_ADDR.rpartition(":")
    port = int(port)
    server = ThreadingHTTPServer((host, port), GateHandler)
    print(f"INFO maintenance-gate listening on {LISTEN_ADDR}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
