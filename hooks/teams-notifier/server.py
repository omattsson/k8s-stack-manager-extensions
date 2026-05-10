#!/usr/bin/env python3
"""Teams notifier — posts deploy results to Microsoft Teams via Incoming Webhook.

Subscribes to deploy-finalized events from k8s-stack-manager and sends
a formatted Adaptive Card message with instance details.

Inbound requests are accepted immediately and Teams posts are processed by a
fixed-size worker pool, so thread count stays bounded under load.

Card rendering uses a JSON template file (CARD_TEMPLATE_FILE) with
{{variable}} placeholders. When no template is configured, falls back to
a built-in Adaptive Card.

Usage:
    export TEAMS_WEBHOOK_URL="https://your-tenant.webhook.office.com/webhookb2/..."
    export TEAMS_WEBHOOK_SECRET="your-shared-secret"
    export SITE_DOMAIN="klaravik.test"          # optional, used in card template
    export CARD_TEMPLATE_FILE="/config/card.json" # optional, path to card template
    python3 server.py
"""

import hashlib
import hmac
import json
import os
import queue
import re
import sys
import urllib.request
import urllib.error
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")
SECRET = os.environ.get("TEAMS_WEBHOOK_SECRET", "")
STACK_MANAGER_URL = os.environ.get("STACK_MANAGER_URL", "https://stack-manager.example")
SITE_DOMAIN = os.environ.get("SITE_DOMAIN", "localhost")
CARD_TEMPLATE_FILE = os.environ.get("CARD_TEMPLATE_FILE", "")
LISTEN_ADDR = os.environ.get("LISTEN_ADDR", ":8080")
WORKER_COUNT = int(os.environ.get("TEAMS_WORKER_COUNT", "4"))
QUEUE_SIZE = int(os.environ.get("TEAMS_QUEUE_SIZE", "500"))

_work_queue = queue.Queue(maxsize=QUEUE_SIZE)
_dropped = 0
_dropped_lock = threading.Lock()

_card_template: str | None = None


def load_card_template() -> str | None:
    if not CARD_TEMPLATE_FILE:
        return None
    try:
        with open(CARD_TEMPLATE_FILE) as f:
            return f.read()
    except FileNotFoundError:
        print(f"WARN card template not found: {CARD_TEMPLATE_FILE}", file=sys.stderr, flush=True)
        return None


def render_template(template: str, variables: dict[str, str]) -> dict:
    rendered = re.sub(
        r"\{\{(\w+)\}\}",
        lambda m: variables.get(m.group(1), m.group(0)),
        template,
    )
    return json.loads(rendered)


def build_template_variables(envelope: dict) -> dict[str, str]:
    instance = envelope.get("instance", {})
    name = instance.get("name", "unknown")
    status = instance.get("status", "")
    instance_id = instance.get("id", "")

    is_success = status in ("deployed", "running")

    return {
        "name": name,
        "namespace": instance.get("namespace", "unknown"),
        "branch": instance.get("branch", "unknown"),
        "cluster_id": instance.get("cluster_id", ""),
        "status": status,
        "instance_id": instance_id,
        "emoji": "✅" if is_success else "❌",
        "outcome": "succeeded" if is_success else "failed",
        "color": "good" if is_success else "attention",
        "instance_url": f"{STACK_MANAGER_URL}/stack-instances/{instance_id}",
        "site_url": f"https://{name}.{SITE_DOMAIN}",
        "site_domain": SITE_DOMAIN,
        "stack_manager_url": STACK_MANAGER_URL,
    }


def verify_signature(body: bytes, signature: str) -> bool:
    if not SECRET:
        return True
    expected = "sha256=" + hmac.new(
        SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def build_adaptive_card(envelope: dict) -> dict:
    global _card_template
    if _card_template is not None:
        variables = build_template_variables(envelope)
        return render_template(_card_template, variables)

    instance = envelope.get("instance", {})
    name = instance.get("name", "unknown")
    namespace = instance.get("namespace", "unknown")
    branch = instance.get("branch", "unknown")
    cluster_id = instance.get("cluster_id", "")
    status = instance.get("status", "")
    instance_id = instance.get("id", "")

    is_success = status in ("deployed", "running")
    emoji = "✅" if is_success else "❌"
    outcome = "succeeded" if is_success else "failed"
    color = "good" if is_success else "attention"

    instance_url = f"{STACK_MANAGER_URL}/stack-instances/{instance_id}"
    site_url = f"https://{name}.{SITE_DOMAIN}"

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
                            "text": f"{emoji} Deploy {outcome} — {name}",
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
                            "title": "Open site",
                            "url": site_url,
                        },
                        {
                            "type": "Action.OpenUrl",
                            "title": "Stack Manager",
                            "url": instance_url,
                        },
                    ],
                },
            }
        ],
    }

    return card


# --- Notification channel payload support ---
# Generic payloads from k8s-stack-manager notification channels have "event_type"
# instead of "event". The extension formats these into Adaptive Cards.

NOTIFICATION_COLORS: dict[str, str] = {
    "deployment.success": "good",
    "deployment.error": "attention",
    "deployment.partial": "warning",
    "deploy.timeout": "attention",
    "clean.error": "attention",
    "rollback.error": "attention",
    "stop.error": "attention",
    "stack.expiring": "warning",
    "stack.expired": "warning",
    "quota.warning": "warning",
    "secret.expiring": "warning",
}

NOTIFICATION_EMOJIS: dict[str, str] = {
    "good": "✅",
    "attention": "❌",
    "warning": "⚠️",
}


def build_notification_card(payload: dict) -> dict:
    """Build an Adaptive Card from a generic notification channel payload."""
    global _card_template

    event_type = payload.get("event_type", "unknown")
    title = payload.get("title", "Notification")
    message = payload.get("message", "")
    user = payload.get("user_display_name", "")
    entity_type = payload.get("entity_type", "")
    entity_id = payload.get("entity_id", "")

    if _card_template is not None:
        variables = {
            "event_type": event_type,
            "title": title,
            "message": message,
            "user_display_name": user,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "stack_manager_url": STACK_MANAGER_URL,
            "site_domain": SITE_DOMAIN,
        }
        return render_template(_card_template, variables)

    color = NOTIFICATION_COLORS.get(event_type, "default")
    emoji = NOTIFICATION_EMOJIS.get(color, "ℹ️")

    heading = f"{emoji} {title}"
    if user and user != "System":
        heading += f" — {user}"

    body: list[dict] = [
        {
            "type": "TextBlock",
            "size": "medium",
            "weight": "bolder",
            "text": heading,
            "style": "heading",
            "color": color,
            "wrap": True,
        },
    ]

    if message:
        body.append({
            "type": "TextBlock",
            "text": message,
            "wrap": True,
        })

    facts = [{"title": "Event", "value": event_type}]
    if user:
        facts.append({"title": "User", "value": user})
    if entity_type:
        facts.append({"title": "Entity", "value": f"{entity_type}/{entity_id}"})

    body.append({"type": "FactSet", "facts": facts})

    actions: list[dict] = []
    if entity_type and entity_id:
        entity_url = f"{STACK_MANAGER_URL}/{entity_type.replace('_', '-')}s/{entity_id}"
        actions.append({
            "type": "Action.OpenUrl",
            "title": "View in Dashboard",
            "url": entity_url,
        })

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                    "actions": actions,
                },
            }
        ],
    }


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

        # Detect payload format: notification channels use "event_type",
        # hooks use "event".
        if "event_type" in envelope:
            event_type = envelope.get("event_type", "")
            user = envelope.get("user_display_name", "")
            print(
                f"INFO notification event_type={event_type} user={user}",
                flush=True,
            )
            if TEAMS_WEBHOOK_URL:
                card = build_notification_card(envelope)
                enqueue_card(card)
        else:
            event = envelope.get("event", "")
            instance = envelope.get("instance", {})
            request_id = envelope.get("request_id", "")
            print(
                f"INFO hook event={event} instance={instance.get('name', '?')} request_id={request_id}",
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
    global _card_template

    if not TEAMS_WEBHOOK_URL:
        print("FATAL TEAMS_WEBHOOK_URL is required", file=sys.stderr, flush=True)
        sys.exit(1)
    if not SECRET:
        print("WARN TEAMS_WEBHOOK_SECRET not set -- signature verification disabled", file=sys.stderr, flush=True)

    _card_template = load_card_template()
    if _card_template:
        print(f"INFO loaded card template from {CARD_TEMPLATE_FILE}", flush=True)

    print(
        f"INFO teams-notifier workers={WORKER_COUNT} queue_size={QUEUE_SIZE} site_domain={SITE_DOMAIN}",
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
