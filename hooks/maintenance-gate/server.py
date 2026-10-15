#!/usr/bin/env python3
"""Maintenance gate — blocks deploys outside configurable business hours and
while an operator has switched maintenance on.

Subscribes to pre-deploy (and pre-rollback) events from k8s-stack-manager with
failure_policy=fail. Returns {"allowed": false} when the current time is
outside the permitted window (SCHEDULE_ENABLED) or when the maintenance switch
(a ConfigMap, STATE_CONFIGMAP) is on.

Usage:
    export GATE_WEBHOOK_SECRET="your-shared-secret"
    python3 server.py
"""

import hashlib
import hmac
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
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
# The schedule applies to pre-deploy only: an emergency rollback at night must work.
SCHEDULE_ENABLED = os.environ.get("SCHEDULE_ENABLED", "true").strip().lower() not in ("false", "0", "no", "off")

# Maintenance switch: a ConfigMap with the key state.json, read through the
# Kubernetes API. Unset STATE_CONFIGMAP turns the switch off.
STATE_CONFIGMAP = os.environ.get("STATE_CONFIGMAP", "")
STATE_KEY = "state.json"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
SA_TOKEN_FILE = os.environ.get("SA_TOKEN_FILE", SA_DIR + "/token")
SA_CA_FILE = os.environ.get("SA_CA_FILE", SA_DIR + "/ca.crt")
STATE_CACHE_SECONDS = float(os.environ.get("STATE_CACHE_SECONDS", "5"))
API_TIMEOUT_SECONDS = 2.0

TZ = ZoneInfo(TZ_NAME)

DAY_ABBREVS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _default_namespace() -> str:
    """The pod namespace from the service account, or "extensions"."""
    try:
        with open(SA_DIR + "/namespace", encoding="utf-8") as f:
            return f.read().strip() or "extensions"
    except OSError:
        return "extensions"


STATE_NAMESPACE = os.environ.get("STATE_NAMESPACE", "") or _default_namespace()


def _api_base_url() -> str:
    """The Kubernetes API URL. K8S_API_URL overrides it (tests)."""
    override = os.environ.get("K8S_API_URL", "")
    if override:
        return override.rstrip("/")
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        raise RuntimeError("not running in a cluster (KUBERNETES_SERVICE_HOST is not set)")
    if ":" in host:  # IPv6
        host = f"[{host}]"
    return f"https://{host}:{port}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: a redirect would carry the token to another URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(https: bool) -> urllib.request.OpenerDirector:
    """An opener without proxies and without redirects."""
    handlers = [urllib.request.ProxyHandler({}), _NoRedirect()]
    if https:
        context = ssl.create_default_context(cafile=SA_CA_FILE if os.path.exists(SA_CA_FILE) else None)
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def fetch_state_configmap() -> dict | None:
    """Read the state ConfigMap. Returns its data map, or None when the
    ConfigMap does not exist. Raises on any other error."""
    url = (f"{_api_base_url()}/api/v1/namespaces/{urllib.parse.quote(STATE_NAMESPACE, safe='')}"
           f"/configmaps/{urllib.parse.quote(STATE_CONFIGMAP, safe='')}")
    https = url.startswith("https://")
    headers = {"Accept": "application/json"}
    if https:  # never send the token in clear text
        try:
            with open(SA_TOKEN_FILE, encoding="utf-8") as f:
                headers["Authorization"] = "Bearer " + f.read().strip()
        except OSError:
            pass  # no token: the API answers 401/403, which closes the gate
    req = urllib.request.Request(url, headers=headers)
    try:
        with _opener(https).open(req, timeout=API_TIMEOUT_SECONDS) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise RuntimeError(f"Kubernetes API answered HTTP {e.code}") from e
    if not isinstance(body, dict):
        raise RuntimeError("Kubernetes API answer is not a JSON object")
    data = body.get("data") or {}
    if not isinstance(data, dict):
        raise RuntimeError("ConfigMap data is not a map")
    return data


def parse_until(value) -> datetime:
    """Parse an RFC 3339 time with a time zone ("Z" or an offset)."""
    if not isinstance(value, str):
        raise ValueError("until is not a string")
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("until needs a time zone")
    return dt


def _evaluate(data: dict | None, now: datetime) -> tuple[bool, str, datetime | None]:
    """evaluate_state plus the end time of a closed switch (for the cache)."""
    if not data or STATE_KEY not in data:
        return True, "", None
    try:
        state = json.loads(data[STATE_KEY])
        if not isinstance(state, dict):
            raise ValueError("state.json is not a JSON object")
        if "enabled" not in state:
            raise ValueError("enabled is missing")
        enabled = state["enabled"]
        if not isinstance(enabled, bool):
            raise ValueError("enabled is not true or false")
        until = parse_until(state["until"]) if state.get("until") else None
        if not enabled or (until is not None and until <= now):
            return True, "", None
        reason = str(state.get("reason") or "platform maintenance")
        message = f"Deploys paused: {reason}"
        if until is not None:
            message += f" (until {until.astimezone(TZ).strftime('%Y-%m-%d %H:%M')} {TZ_NAME})"
        return False, message, until
    except (ValueError, KeyError, TypeError, OverflowError) as e:
        return False, f"Deploys paused: the maintenance state is not valid ({e})", None


def evaluate_state(data: dict | None, now: datetime) -> tuple[bool, str]:
    """Decide from the ConfigMap data. Returns (allowed, message).

    No ConfigMap, no state.json, enabled false, or an until in the past
    means no maintenance. A state.json that is not valid (also a missing
    "enabled") closes the gate."""
    allowed, message, _ = _evaluate(data, now)
    return allowed, message


_state_lock = threading.Lock()
# (monotonic fetch time, allowed, message, until of a closed switch)
_state_cache: tuple[float, bool, str, datetime | None] | None = None


def maintenance_check() -> tuple[bool, str]:
    """Check the maintenance switch (cached for STATE_CACHE_SECONDS).
    An API error closes the gate (fail closed)."""
    global _state_cache
    if not STATE_CONFIGMAP:
        return True, ""
    with _state_lock:
        now_mono = time.monotonic()
        cached = _state_cache
        if cached is not None and now_mono - cached[0] < STATE_CACHE_SECONDS:
            expired = cached[3] is not None and cached[3] <= datetime.now(timezone.utc)
            if not expired:
                return cached[1], cached[2]
        try:
            allowed, message, until = _evaluate(fetch_state_configmap(), datetime.now(timezone.utc))
        except Exception as e:  # noqa: BLE001 - any failure closes the gate
            print(f"ERROR maintenance state read failed: {e}", file=sys.stderr, flush=True)
            allowed, message, until = False, "Deploys paused: the maintenance state cannot be read", None
        _state_cache = (now_mono, allowed, message, until)
        return allowed, message


def cached_maintenance_state() -> tuple[bool | None, str]:
    """The last switch decision without an API call (for /healthz).
    None means unknown (no request yet)."""
    if not STATE_CONFIGMAP:
        return True, ""
    cached = _state_cache  # a tuple swap is atomic
    if cached is None:
        return None, "maintenance state not read yet"
    if cached[3] is not None and cached[3] <= datetime.now(timezone.utc):
        return True, ""  # the switch has expired since the last read
    return cached[1], cached[2]


def check_gate(event: str = "pre-deploy") -> tuple[bool, str]:
    """The full gate decision: the maintenance switch first, then the
    schedule (when SCHEDULE_ENABLED, for pre-deploy only)."""
    allowed, message = maintenance_check()
    if not allowed:
        return allowed, message
    if SCHEDULE_ENABLED and event != "pre-rollback":
        return is_deploy_allowed()
    return True, ""


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
            # Always 200 and never an API call: a slow Kubernetes API (for
            # example during a CNI upgrade) must not fail the probes.
            allowed, msg = cached_maintenance_state()
            if allowed and SCHEDULE_ENABLED:
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

        # Check the maintenance switch and the deploy window
        allowed, message = check_gate(str(envelope.get("event", "pre-deploy")))
        print(
            f"INFO gate={'open' if allowed else 'closed'} event={envelope.get('event', '?')} instance={instance.get('name', '?')} request_id={request_id}",
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
        f"INFO maintenance-gate starting schedule_enabled={SCHEDULE_ENABLED} "
        f"schedule={','.join(ALLOWED_DAYS)} "
        f"hours={ALLOWED_START_HOUR:02d}-{ALLOWED_END_HOUR:02d} tz={TZ_NAME} "
        f"state_configmap={(STATE_NAMESPACE + '/' + STATE_CONFIGMAP) if STATE_CONFIGMAP else 'off'}",
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
