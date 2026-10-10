#!/usr/bin/env python3
"""Teams notifier — posts stack lifecycle events to Microsoft Teams.

Subscribes to k8s-stack-manager lifecycle hooks (deploy-finalized,
deploy-timeout, stop-completed, clean-completed, delete-completed,
rollback-completed, cleanup-policy-executed) and posts an Adaptive Card per
event to a Teams Workflows webhook. TEAMS_EVENTS limits the events that
post a card.

Inbound requests are accepted immediately and Teams posts are processed by a
fixed-size worker pool, so thread count stays bounded under load.

Card rendering uses a JSON template file (CARD_TEMPLATE_FILE) with
{{variable}} placeholders. When no template is configured, falls back to
a built-in Adaptive Card.

Usage:
    export TEAMS_WEBHOOK_URL="https://your-tenant.webhook.office.com/webhookb2/..."
    export TEAMS_WEBHOOK_SECRET="your-shared-secret"
    export SITE_DOMAIN="example.test"          # optional, used in card template
    export CARD_TEMPLATE_FILE="/config/card.json" # optional, path to card template
    export TEAMS_EVENTS="deploy-finalized,stop-completed" # optional allow list
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

# Hook events that post a card. TEAMS_EVENTS (comma separated) limits them.
# deploy-timeout is not in the default list: deploy-finalized also fires for a
# timed-out deploy and its "Deploy failed" card covers it. Add deploy-timeout
# to TEAMS_EVENTS to get a separate "Deploy timed out" card.
DEFAULT_TEAMS_EVENTS = (
    "deploy-finalized",
    "stop-completed",
    "clean-completed",
    "delete-completed",
    "rollback-completed",
    "cleanup-policy-executed",
)


# All hook events that this hook can post a card for.
KNOWN_TEAMS_EVENTS = frozenset(DEFAULT_TEAMS_EVENTS) | {"deploy-timeout"}


def parse_bool(value: str, default: bool = False) -> bool:
    value = value.strip().lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


def parse_events(value: str) -> frozenset[str]:
    """Parse the TEAMS_EVENTS allow list. Empty means all default events."""
    events = {e.strip() for e in value.split(",") if e.strip()}
    return frozenset(events) if events else frozenset(DEFAULT_TEAMS_EVENTS)


TEAMS_EVENTS = parse_events(os.environ.get("TEAMS_EVENTS", ""))

# The cleanup-policy-executed summary card lists the stacks of a policy run,
# so the successful stop/clean/delete cards of that run are skipped. Set
# TEAMS_POLICY_INSTANCE_CARDS=true to post them too. Failed operations
# (status error) always post a card: the summary only says that they started.
TEAMS_POLICY_INSTANCE_CARDS = parse_bool(os.environ.get("TEAMS_POLICY_INSTANCE_CARDS", ""))


def unknown_events(events) -> list[str]:
    """Return the names in events that this hook has no card for."""
    return sorted(set(events) - KNOWN_TEAMS_EVENTS)

# Number of stacks listed in a cleanup-policy-executed card.
MAX_POLICY_LINES = 20

_work_queue = queue.Queue(maxsize=QUEUE_SIZE)
_dropped = 0
_dropped_lock = threading.Lock()

_card_template: str | None = None


# Adaptive Card TextBlock and FactSet values render a markdown subset.
# Names, branches and error texts come from users, so escape what can build
# a link ([text](url)) and the markers at a line start (heading, list, quote).
# "_" and "*" inside a word stay as they are, so a branch like feature/foo_bar
# renders as written. A backslash is escaped too, so it cannot undo an escape.
_MD_SPECIALS = re.compile(r"([\\\[\]()])")
_MD_LINE_START = re.compile(r"^(\s*)([#>*+-]|\d+\.)", re.MULTILINE)


def md(text) -> str:
    """Escape Adaptive Card markdown in user-controlled text."""
    text = _MD_SPECIALS.sub(r"\\\1", str(text))
    return _MD_LINE_START.sub(_escape_line_start, text)


def _escape_line_start(m: re.Match) -> str:
    marker = m.group(2)
    if marker.endswith("."):
        # An ordered list item "1." becomes "1\.".
        return m.group(1) + marker[:-1] + "\\."
    return m.group(1) + "\\" + marker


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
    namespace = md(instance.get("namespace", "unknown"))
    branch = md(instance.get("branch", "unknown"))
    cluster_id = md(instance.get("cluster_id", ""))
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
                            "text": f"{emoji} Deploy {outcome} — {md(name)}",
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


# --- Lifecycle event cards (stop, clean, delete, rollback, timeout, policy) ---


def trigger_text(envelope: dict) -> str:
    """Return who or what started the operation, or "" when unknown."""
    trigger = envelope.get("trigger") or {}
    kind = trigger.get("type", "")
    name = trigger.get("name") or trigger.get("id") or ""
    if kind == "cleanup-policy":
        return f"cleanup policy {name}".strip()
    if kind == "ttl":
        return "TTL expiry"
    if kind == "user":
        return name or "a user"
    return kind


def _instance_facts(instance: dict, trigger: str) -> list[dict]:
    facts = [
        {"title": "Namespace", "value": md(instance.get("namespace", "unknown"))},
        {"title": "Branch", "value": md(instance.get("branch", "unknown"))},
    ]
    if instance.get("cluster_id"):
        facts.append({"title": "Cluster", "value": md(instance["cluster_id"])})
    if trigger:
        facts.append({"title": "Triggered by", "value": md(trigger)})
    return facts


def _message_card(heading: str, color: str, body: list[dict], actions: list[dict]) -> dict:
    blocks = [
        {
            "type": "TextBlock",
            "size": "medium",
            "weight": "bolder",
            "text": heading,
            "style": "heading",
            "color": color,
            "wrap": True,
        },
        *body,
    ]
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
                    "body": blocks,
                    "actions": actions,
                },
            }
        ],
    }


def _instance_title(envelope: dict) -> tuple[str, str, str]:
    """Return (emoji, title, color) for an instance lifecycle event."""
    event = envelope.get("event", "")
    status = (envelope.get("instance") or {}).get("status", "")
    failed = status == "error"
    if event == "stop-completed":
        return ("❌", "Stop failed", "attention") if failed else ("⏹", "Stack stopped", "default")
    if event == "clean-completed":
        return ("❌", "Clean failed", "attention") if failed else ("🧹", "Stack cleaned", "default")
    if event == "delete-completed":
        return ("🗑", "Stack deleted", "default")
    if event == "deploy-timeout":
        return ("⏱", "Deploy timed out", "attention")
    if event == "rollback-completed":
        outcome = (envelope.get("metadata") or {}).get("outcome", "")
        if outcome == "succeeded":
            return ("↩", "Rollback succeeded", "good")
        if outcome == "rejected":
            return ("⛔", "Rollback rejected", "warning")
        if outcome == "cancelled":
            return ("⚠️", "Rollback cancelled", "warning")
        return ("❌", "Rollback failed", "attention")
    return ("ℹ️", event, "default")


def build_event_card(envelope: dict) -> dict:
    """Build the card of a stop, clean, delete, rollback or timeout event."""
    instance = envelope.get("instance") or {}
    name = instance.get("name", "unknown")
    instance_id = instance.get("id", "")
    emoji, title, color = _instance_title(envelope)
    trigger = trigger_text(envelope)

    body: list[dict] = []
    if trigger:
        body.append({"type": "TextBlock", "text": f"{title} by {md(trigger)}", "wrap": True, "isSubtle": True})
    body.append({"type": "FactSet", "facts": _instance_facts(instance, trigger)})

    actions: list[dict] = []
    # A deleted stack has no page any more.
    if envelope.get("event") != "delete-completed" and instance_id:
        actions.append({
            "type": "Action.OpenUrl",
            "title": "Stack Manager",
            "url": f"{STACK_MANAGER_URL}/stack-instances/{instance_id}",
        })
    return _message_card(f"{emoji} {title} — {md(name)}", color, body, actions)


def build_policy_card(envelope: dict) -> dict:
    """Build the summary card of a cleanup-policy-executed event."""
    run = envelope.get("cleanup_policy") or {}
    name = run.get("name") or run.get("id") or "unknown"
    action = run.get("action", "")
    matched = run.get("matched", len(run.get("instances") or []))
    failed = run.get("failed", 0)
    heading = f"🧹 Cleanup policy {md(name)}: {md(action)} on {matched} stack(s)"
    if run.get("dry_run"):
        heading += " (dry run)"
    color = "attention" if failed else "default"

    instances = run.get("instances") or []
    lines = []
    for inst in instances[:MAX_POLICY_LINES]:
        line = f"- {md(inst.get('name', inst.get('id', '?')))}: {md(inst.get('result', ''))}"
        if inst.get("error"):
            line += f" — {md(inst['error'])}"
        lines.append(line)
    hidden = max(matched - len(lines), 0)
    if hidden:
        lines.append(f"- and {hidden} more")

    facts = [
        {"title": "Cluster", "value": md(run.get("cluster_id", ""))},
        {"title": "Run", "value": md(run.get("run", ""))},
        {"title": "Succeeded", "value": str(run.get("succeeded", 0))},
        {"title": "Failed", "value": str(failed)},
    ]
    if run.get("condition"):
        facts.insert(1, {"title": "Condition", "value": md(run["condition"])})

    body: list[dict] = []
    if lines:
        body.append({"type": "TextBlock", "text": "\n".join(lines), "wrap": True})
    body.append({"type": "FactSet", "facts": facts})
    actions = [{
        "type": "Action.OpenUrl",
        "title": "Cleanup policies",
        "url": f"{STACK_MANAGER_URL}/admin/cleanup-policies",
    }]
    return _message_card(heading, color, body, actions)


def is_clean_of_delete(envelope: dict) -> bool:
    """True for the successful clean-completed of a delete.

    k8s-stack-manager sets metadata.operation=delete when delete-completed
    follows, so the delete card alone tells the story. A failed clean has
    no delete and keeps its card.
    """
    if envelope.get("event") != "clean-completed":
        return False
    status = (envelope.get("instance") or {}).get("status", "")
    return (envelope.get("metadata") or {}).get("operation") == "delete" and status != "error"


def is_policy_instance_event(envelope: dict) -> bool:
    """True for a successful stop/clean/delete that a cleanup policy started."""
    if envelope.get("event") not in ("stop-completed", "clean-completed", "delete-completed"):
        return False
    if (envelope.get("trigger") or {}).get("type") != "cleanup-policy":
        return False
    return (envelope.get("instance") or {}).get("status", "") != "error"


def skip_reason(envelope: dict) -> str:
    """Return why an allowed event posts no card, or "" when it posts one."""
    if is_clean_of_delete(envelope):
        return "delete-completed follows"
    if is_policy_instance_event(envelope) and not TEAMS_POLICY_INSTANCE_CARDS:
        return "covered by the cleanup-policy-executed card"
    return ""


def build_hook_card(envelope: dict) -> dict | None:
    """Return the card of a hook event, or None when the event posts no card."""
    event = envelope.get("event", "")
    if event not in TEAMS_EVENTS:
        return None
    if skip_reason(envelope):
        return None
    if event == "deploy-finalized":
        return build_adaptive_card(envelope)
    if event == "cleanup-policy-executed":
        return build_policy_card(envelope)
    if event in ("deploy-timeout", "stop-completed", "clean-completed", "delete-completed", "rollback-completed"):
        return build_event_card(envelope)
    return None


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
            "event_type": json.dumps(str(event_type))[1:-1],
            "title": json.dumps(str(title))[1:-1],
            "message": json.dumps(str(message))[1:-1],
            "user_display_name": json.dumps(str(user or ""))[1:-1],
            "entity_type": json.dumps(str(entity_type or ""))[1:-1],
            "entity_id": json.dumps(str(entity_id or ""))[1:-1],
            "stack_manager_url": json.dumps(str(STACK_MANAGER_URL or ""))[1:-1],
            "site_domain": json.dumps(str(SITE_DOMAIN or ""))[1:-1],
        }
        try:
            return render_template(_card_template, variables)
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"WARN template render failed, using fallback card: {exc}", file=sys.stderr, flush=True)

    color = NOTIFICATION_COLORS.get(event_type, "default")
    emoji = NOTIFICATION_EMOJIS.get(color, "ℹ️")

    heading = f"{emoji} {md(title)}"
    if user and user != "System":
        heading += f" — {md(user)}"

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
            "text": md(message),
            "wrap": True,
        })

    facts = [{"title": "Event", "value": md(event_type)}]
    if user:
        facts.append({"title": "User", "value": md(user)})
    if entity_type and entity_id:
        facts.append({"title": "Entity", "value": md(f"{entity_type}/{entity_id}")})

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


def post_to_teams(payload: dict, meta: dict | None = None) -> None:
    """Post a card. meta ({"event", "instance"}) goes into the log lines."""
    meta = meta or {}
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
            print(
                f"INFO posted event={meta.get('event', '?')} instance={meta.get('instance', '?')} status={resp.status}",
                flush=True,
            )
    except urllib.error.URLError as exc:
        print(f"WARN teams post failed event={meta.get('event', '?')}: {exc}", file=sys.stderr, flush=True)


def _worker():
    while True:
        item = _work_queue.get()
        if item is None:
            break
        try:
            if isinstance(item, tuple):
                post_to_teams(*item)
            else:
                post_to_teams(item)
        except Exception as exc:
            print(f"ERROR worker unhandled exception: {exc}", file=sys.stderr, flush=True)
        finally:
            _work_queue.task_done()


def enqueue_card(card: dict, event: str = "", instance: str = "") -> bool:
    """Enqueue a card for async delivery. Returns False if queue is full."""
    global _dropped
    item = (card, {"event": event, "instance": instance}) if event else card
    try:
        _work_queue.put_nowait(item)
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
                enqueue_card(card, event=event_type, instance=envelope.get("entity_id", ""))
        else:
            event = envelope.get("event", "")
            instance = envelope.get("instance", {})
            request_id = envelope.get("request_id", "")
            print(
                f"INFO hook event={event} instance={instance.get('name', '?')} request_id={request_id}",
                flush=True,
            )
            if not TEAMS_WEBHOOK_URL:
                pass
            elif event not in TEAMS_EVENTS:
                print(f"INFO ignored event={event} (not in TEAMS_EVENTS)", flush=True)
            else:
                card = build_hook_card(envelope)
                reason = skip_reason(envelope)
                if card is None and reason:
                    print(f"INFO skipped event={event} instance={instance.get('name', '?')} ({reason})", flush=True)
                if card is not None:
                    name = instance.get("name") or (envelope.get("cleanup_policy") or {}).get("name", "?")
                    enqueue_card(card, event=event, instance=name)

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

    unknown = unknown_events(TEAMS_EVENTS)
    if unknown:
        print(f"WARN TEAMS_EVENTS has events without a card: {','.join(unknown)}", file=sys.stderr, flush=True)

    _card_template = load_card_template()
    if _card_template:
        print(f"INFO loaded card template from {CARD_TEMPLATE_FILE}", flush=True)

    print(
        f"INFO teams-notifier workers={WORKER_COUNT} queue_size={QUEUE_SIZE} site_domain={SITE_DOMAIN} "
        f"events={','.join(sorted(TEAMS_EVENTS))}",
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
