#!/usr/bin/env python3
import hashlib
import hmac
import http.client
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import server

SAMPLE_ENVELOPE = {
    "apiVersion": "hooks.k8sstackmanager.io/v1",
    "kind": "EventEnvelope",
    "event": "pre-deploy",
    "request_id": "req-abc123",
    "instance": {
        "id": "inst-001",
        "name": "demo",
        "namespace": "stack-demo-alice",
        "branch": "main",
        "cluster_id": "dev",
        "status": "draft",
    },
}

TEST_SECRET = "test-secret-key"


def _sign(body: bytes, secret: str = TEST_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class TestVerifySignature(unittest.TestCase):
    def test_valid(self):
        body = b'{"event":"test"}'
        with patch.object(server, "SECRET", TEST_SECRET):
            self.assertTrue(server.verify_signature(body, _sign(body)))

    def test_invalid(self):
        with patch.object(server, "SECRET", TEST_SECRET):
            self.assertFalse(server.verify_signature(b"x", "sha256=bad"))

    def test_empty_secret_skips(self):
        with patch.object(server, "SECRET", ""):
            self.assertTrue(server.verify_signature(b"anything", ""))


class TestIsDeployAllowed(unittest.TestCase):
    def test_returns_tuple(self):
        allowed, msg = server.is_deploy_allowed()
        self.assertIsInstance(allowed, bool)
        self.assertIsInstance(msg, str)

    def test_allowed_during_business_hours(self):
        with patch.object(server, "ALLOWED_DAYS", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]), \
             patch.object(server, "ALLOWED_START_HOUR", 0), \
             patch.object(server, "ALLOWED_END_HOUR", 24):
            allowed, msg = server.is_deploy_allowed()
            self.assertTrue(allowed)
            self.assertEqual(msg, "")

    def test_blocked_outside_hours(self):
        with patch.object(server, "ALLOWED_DAYS", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]), \
             patch.object(server, "ALLOWED_START_HOUR", 0), \
             patch.object(server, "ALLOWED_END_HOUR", 0):
            allowed, msg = server.is_deploy_allowed()
            self.assertFalse(allowed)
            self.assertIn("blocked", msg.lower())


class TestHTTPHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), server.GateHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def _conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)

    def test_healthz(self):
        conn = self._conn()
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        body = json.loads(resp.read())
        self.assertEqual(body["status"], "ok")
        self.assertIn("deploys_allowed", body)
        conn.close()

    def test_get_unknown_returns_404(self):
        conn = self._conn()
        conn.request("GET", "/nope")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 404)
        conn.close()

    def test_post_invalid_json_returns_400(self):
        conn = self._conn()
        conn.request("POST", "/hook", body=b"not json", headers={"Content-Length": "8"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        conn.close()

    def test_post_bad_signature_returns_401(self):
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        with patch.object(server, "SECRET", TEST_SECRET):
            conn = self._conn()
            conn.request(
                "POST", "/hook", body=body,
                headers={
                    "Content-Length": str(len(body)),
                    "X-StackManager-Signature": "sha256=wrong",
                },
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            conn.close()

    def test_post_returns_allowed_field(self):
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        with patch.object(server, "SECRET", ""):
            conn = self._conn()
            conn.request(
                "POST", "/hook", body=body,
                headers={"Content-Length": str(len(body))},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read())
            self.assertIn("allowed", data)
            conn.close()

    def test_bypass_header_allows_deploy(self):
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        with patch.object(server, "SECRET", ""), \
             patch.object(server, "BYPASS_HEADER", "letmein"):
            conn = self._conn()
            conn.request(
                "POST", "/hook", body=body,
                headers={
                    "Content-Length": str(len(body)),
                    "X-Bypass-Gate": "letmein",
                },
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read())
            self.assertTrue(data["allowed"])
            conn.close()

    def test_post_with_valid_hmac(self):
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        sig = _sign(body)
        with patch.object(server, "SECRET", TEST_SECRET):
            conn = self._conn()
            conn.request(
                "POST", "/hook", body=body,
                headers={
                    "Content-Length": str(len(body)),
                    "X-StackManager-Signature": sig,
                },
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            conn.close()



class FakeAPI(BaseHTTPRequestHandler):
    """A fake Kubernetes API that serves one ConfigMap answer."""

    status = 404
    data = None
    seen_paths = []
    seen_auth = []

    def do_GET(self):
        FakeAPI.seen_paths.append(self.path)
        FakeAPI.seen_auth.append(self.headers.get("Authorization", ""))
        self.send_response(FakeAPI.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if FakeAPI.status == 200:
            self.wfile.write(json.dumps({"kind": "ConfigMap", "data": FakeAPI.data}).encode())
        else:
            self.wfile.write(b'{"kind":"Status"}')

    def log_message(self, format, *args):
        pass


def _state(**fields) -> dict:
    return {"state.json": json.dumps(fields)}


NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


class TestEvaluateState(unittest.TestCase):
    def test_cases(self):
        future = (NOW + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        past = (NOW - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cases = [
            ("no configmap", None, True, ""),
            ("no state key", {"other": "x"}, True, ""),
            ("disabled", _state(enabled=False, reason="x"), True, ""),
            ("enabled without until", _state(enabled=True, reason="CNI upgrade"), False, "Deploys paused: CNI upgrade"),
            ("enabled until future", _state(enabled=True, reason="CNI upgrade", until=future), False, "(until 2026-10-15 14:30"),
            ("enabled until past", _state(enabled=True, reason="CNI upgrade", until=past), True, ""),
            ("default reason", _state(enabled=True), False, "Deploys paused: platform maintenance"),
            ("malformed json", {"state.json": "{not json"}, False, "not valid"),
            ("not an object", {"state.json": "[1]"}, False, "not valid"),
            ("enabled not bool", _state(enabled="yes"), False, "not valid"),
            ("until without zone", _state(enabled=True, until="2026-10-15T14:00:00"), False, "not valid"),
            ("until not a string", _state(enabled=True, until=123), False, "until is not a string"),
            ("enabled missing", _state(enable=True), False, "enabled is missing"),
        ]
        for name, data, want_allowed, want_msg in cases:
            with self.subTest(name), patch.object(server, "TZ", server.ZoneInfo("Europe/Stockholm")), \
                    patch.object(server, "TZ_NAME", "Europe/Stockholm"):
                allowed, msg = server.evaluate_state(data, NOW)
                self.assertEqual(want_allowed, allowed)
                self.assertIn(want_msg, msg)


class TestMaintenanceSwitch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = HTTPServer(("127.0.0.1", 0), FakeAPI)
        cls.api_url = f"http://127.0.0.1:{cls.api.server_address[1]}"
        cls.thread = threading.Thread(target=cls.api.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.api.shutdown()
        cls.api.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        server._state_cache = None
        FakeAPI.status, FakeAPI.data = 404, None
        FakeAPI.seen_paths, FakeAPI.seen_auth = [], []
        self.patches = [
            patch.dict("os.environ", {"K8S_API_URL": self.api_url}),
            patch.object(server, "STATE_CONFIGMAP", "maintenance-gate-state"),
            patch.object(server, "STATE_NAMESPACE", "extensions"),
            patch.object(server, "STATE_CACHE_SECONDS", 0),
            patch.object(server, "SA_TOKEN_FILE", "/nonexistent/token"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        server._state_cache = None

    def test_missing_configmap_allows(self):
        self.assertEqual((True, ""), server.maintenance_check())
        self.assertEqual(["/api/v1/namespaces/extensions/configmaps/maintenance-gate-state"], FakeAPI.seen_paths)

    def test_enabled_closes(self):
        FakeAPI.status, FakeAPI.data = 200, _state(enabled=True, reason="CNI upgrade")
        allowed, msg = server.maintenance_check()
        self.assertFalse(allowed)
        self.assertEqual("Deploys paused: CNI upgrade", msg)

    def test_api_error_fails_closed(self):
        FakeAPI.status = 403
        allowed, msg = server.maintenance_check()
        self.assertFalse(allowed)
        self.assertIn("cannot be read", msg)

    def test_unreachable_api_fails_closed(self):
        with patch.dict("os.environ", {"K8S_API_URL": "http://127.0.0.1:1"}):
            allowed, _ = server.maintenance_check()
        self.assertFalse(allowed)

    def test_switch_off_when_configmap_not_set(self):
        with patch.object(server, "STATE_CONFIGMAP", ""):
            FakeAPI.status, FakeAPI.data = 200, _state(enabled=True)
            self.assertEqual((True, ""), server.maintenance_check())
        self.assertEqual([], FakeAPI.seen_paths)

    def test_token_never_sent_over_http(self):
        with tempfile.NamedTemporaryFile("w", suffix="token", delete=False) as f:
            f.write("sa-token\n")
        self.addCleanup(os.unlink, f.name)
        with patch.object(server, "SA_TOKEN_FILE", f.name):
            server.maintenance_check()
        self.assertEqual([""], FakeAPI.seen_auth)

    def test_non_object_answer_fails_closed(self):
        FakeAPI.status, FakeAPI.data = 200, ["not", "a", "map"]
        allowed, msg = server.maintenance_check()
        self.assertFalse(allowed)
        self.assertIn("cannot be read", msg)

    def test_error_is_cached_then_refetched(self):
        FakeAPI.status = 500
        clock = [1000.0]
        with patch.object(server, "STATE_CACHE_SECONDS", 5), \
                patch.object(server.time, "monotonic", lambda: clock[0]):
            self.assertFalse(server.maintenance_check()[0])
            FakeAPI.status = 404
            self.assertFalse(server.maintenance_check()[0], "the cached error is used")
            clock[0] += 6
            self.assertEqual((True, ""), server.maintenance_check())
        self.assertEqual(2, len(FakeAPI.seen_paths))

    def test_cached_closed_reopens_at_until(self):
        until = datetime.now(timezone.utc) + timedelta(seconds=1)
        server._state_cache = (server.time.monotonic(), False, "Deploys paused: x", until)
        FakeAPI.status = 404
        with patch.object(server, "STATE_CACHE_SECONDS", 60):
            self.assertFalse(server.maintenance_check()[0])
            server._state_cache = server._state_cache[:3] + (datetime.now(timezone.utc) - timedelta(seconds=1),)
            self.assertEqual((True, ""), server.maintenance_check())

    def test_healthz_uses_cache_only(self):
        httpd = HTTPServer(("127.0.0.1", 0), server.GateHandler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            with patch.object(server, "SCHEDULE_ENABLED", False):
                conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=5)
                conn.request("GET", "/healthz")
                resp = conn.getresponse()
                unknown = json.loads(resp.read())
                server._state_cache = (server.time.monotonic(), False, "Deploys paused: CNI upgrade", None)
                conn.request("GET", "/healthz")
                resp = conn.getresponse()
                closed = json.loads(resp.read())
                conn.close()
            self.assertEqual(200, resp.status)
            self.assertIsNone(unknown["deploys_allowed"])
            self.assertEqual({"status": "ok", "deploys_allowed": False, "reason": "Deploys paused: CNI upgrade"}, closed)
            self.assertEqual([], FakeAPI.seen_paths, "healthz never calls the API")
        finally:
            httpd.shutdown()
            httpd.server_close()
            t.join(timeout=5)

    def test_schedule_does_not_block_rollbacks(self):
        with patch.object(server, "SCHEDULE_ENABLED", True), \
                patch.object(server, "ALLOWED_DAYS", ["mon"]), \
                patch.object(server, "ALLOWED_START_HOUR", 0), \
                patch.object(server, "ALLOWED_END_HOUR", 0):
            self.assertFalse(server.check_gate("pre-deploy")[0])
            self.assertEqual((True, ""), server.check_gate("pre-rollback"))
            FakeAPI.status, FakeAPI.data = 200, _state(enabled=True, reason="CNI upgrade")
            server._state_cache = None
            self.assertFalse(server.check_gate("pre-rollback")[0], "the switch blocks rollbacks")

    def test_cache(self):
        FakeAPI.status, FakeAPI.data = 200, _state(enabled=True)
        with patch.object(server, "STATE_CACHE_SECONDS", 60):
            server.maintenance_check()
            FakeAPI.data = _state(enabled=False)
            allowed, _ = server.maintenance_check()
        self.assertFalse(allowed, "the cached answer is used")
        self.assertEqual(1, len(FakeAPI.seen_paths))

    def test_check_gate_schedule_disabled(self):
        closed_schedule = [
            patch.object(server, "ALLOWED_DAYS", ["mon"]),
            patch.object(server, "ALLOWED_START_HOUR", 0),
            patch.object(server, "ALLOWED_END_HOUR", 0),
        ]
        for p in closed_schedule:
            p.start()
        try:
            with patch.object(server, "SCHEDULE_ENABLED", False):
                self.assertEqual((True, ""), server.check_gate())
            with patch.object(server, "SCHEDULE_ENABLED", True):
                self.assertFalse(server.check_gate()[0])
        finally:
            for p in closed_schedule:
                p.stop()

    def test_pre_rollback_is_blocked_over_http(self):
        FakeAPI.status, FakeAPI.data = 200, _state(enabled=True, reason="CNI upgrade")
        httpd = HTTPServer(("127.0.0.1", 0), server.GateHandler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            envelope = dict(SAMPLE_ENVELOPE, event="pre-rollback")
            body = json.dumps(envelope).encode()
            with patch.object(server, "SECRET", TEST_SECRET), patch.object(server, "SCHEDULE_ENABLED", False):
                conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=5)
                conn.request("POST", "/hook", body=body, headers={
                    "Content-Length": str(len(body)),
                    "X-StackManager-Signature": _sign(body),
                })
                resp = conn.getresponse()
                data = json.loads(resp.read())
                conn.close()
            self.assertEqual(200, resp.status)
            self.assertEqual({"allowed": False, "message": "Deploys paused: CNI upgrade"}, data)
        finally:
            httpd.shutdown()
            httpd.server_close()
            t.join(timeout=5)

class TestAPIBaseURL(unittest.TestCase):
    def test_ipv6_and_missing_host(self):
        with patch.dict("os.environ", {"KUBERNETES_SERVICE_HOST": "fd00::1", "KUBERNETES_SERVICE_PORT": "443"}, clear=True):
            self.assertEqual("https://[fd00::1]:443", server._api_base_url())
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(RuntimeError):
                server._api_base_url()


if __name__ == "__main__":
    unittest.main()
