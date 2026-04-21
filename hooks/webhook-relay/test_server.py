#!/usr/bin/env python3
import hashlib
import hmac
import http.client
import json
import os
import queue
import tempfile
import threading
import time
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch

import server


SAMPLE_ENVELOPE = {
    "apiVersion": "hooks.k8sstackmanager.io/v1",
    "kind": "EventEnvelope",
    "event": "deploy-finalized",
    "timestamp": "2026-04-18T10:15:32.845Z",
    "request_id": "req-abc123",
    "instance": {
        "id": "inst-001",
        "name": "demo",
        "namespace": "stack-demo-alice",
        "branch": "main",
        "cluster_id": "dev",
        "status": "deployed",
    },
}

TEST_SECRET = "test-secret-key"


def _sign(body: bytes, secret: str = TEST_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Fake destination server — records incoming requests
# ---------------------------------------------------------------------------
class _RecordingHandler(BaseHTTPRequestHandler):
    requests_received = []
    respond_status = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.__class__.requests_received.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": json.loads(body),
        })
        self.send_response(self.__class__.respond_status)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args):
        pass


class _FailHandler(BaseHTTPRequestHandler):
    call_count = 0

    def do_POST(self):
        self.__class__.call_count += 1
        self.send_response(500)
        self.end_headers()
        self.wfile.write(b'{"error":"boom"}')

    def log_message(self, *args):
        pass


class _ForbiddenHandler(BaseHTTPRequestHandler):
    call_count = 0

    def do_POST(self):
        self.__class__.call_count += 1
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b'{"error":"forbidden"}')

    def log_message(self, *args):
        pass


# ---------------------------------------------------------------------------
# Unit tests — pure functions
# ---------------------------------------------------------------------------
class TestVerifySignature(unittest.TestCase):
    def test_valid(self):
        body = b'{"event":"test"}'
        sig = _sign(body)
        with patch.object(server, "SECRET", TEST_SECRET):
            self.assertTrue(server.verify_signature(body, sig))

    def test_invalid(self):
        with patch.object(server, "SECRET", TEST_SECRET):
            self.assertFalse(server.verify_signature(b"x", "sha256=bad"))

    def test_empty_secret_skips(self):
        with patch.object(server, "SECRET", ""):
            self.assertTrue(server.verify_signature(b"x", ""))


class TestLoadDestinations(unittest.TestCase):
    def test_defaults_applied(self):
        with patch.object(server, "DESTINATIONS_JSON", '[{"url":"http://x"}]'):
            dests = server.load_destinations()
            self.assertEqual(dests[0]["name"], "dest-0")
            self.assertEqual(dests[0]["events"], [])
            self.assertEqual(dests[0]["headers"], {})

    def test_preserves_explicit_fields(self):
        cfg = json.dumps([{
            "url": "http://x",
            "name": "my-dest",
            "events": ["post-deploy"],
            "headers": {"X-Foo": "bar"},
        }])
        with patch.object(server, "DESTINATIONS_JSON", cfg):
            dests = server.load_destinations()
            self.assertEqual(dests[0]["name"], "my-dest")
            self.assertEqual(dests[0]["events"], ["post-deploy"])
            self.assertEqual(dests[0]["headers"]["X-Foo"], "bar")


class TestDeliveryLog(unittest.TestCase):
    def test_writes_jsonl(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            with patch.object(server, "LOG_FILE", path):
                server.log_delivery({"event": "test", "ok": True})
                server.log_delivery({"event": "test2", "ok": False})
            with open(path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 2)
            self.assertTrue(json.loads(lines[0])["ok"])
            self.assertFalse(json.loads(lines[1])["ok"])
        finally:
            os.unlink(path)

    def test_noop_when_no_log_file(self):
        with patch.object(server, "LOG_FILE", ""):
            server.log_delivery({"event": "test"})


# ---------------------------------------------------------------------------
# Integration tests — relay_to_destination (called directly, bypasses queue)
# ---------------------------------------------------------------------------
class TestRelayToDestination(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _RecordingHandler.requests_received = []
        _RecordingHandler.respond_status = 200
        cls.dest_server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
        cls.dest_port = cls.dest_server.server_address[1]
        cls.dest_thread = threading.Thread(target=cls.dest_server.serve_forever, daemon=True)
        cls.dest_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.dest_server.shutdown()
        cls.dest_thread.join(timeout=5)

    def setUp(self):
        _RecordingHandler.requests_received = []

    def test_successful_relay(self):
        dest = {
            "name": "test-dest",
            "url": f"http://127.0.0.1:{self.dest_port}/hook",
            "headers": {"X-Custom": "val"},
            "events": [],
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        with patch.object(server, "LOG_FILE", ""), \
             patch.object(server, "MAX_RETRIES", 1):
            server.relay_to_destination(dest, SAMPLE_ENVELOPE, body, "req-001")

        self.assertEqual(len(_RecordingHandler.requests_received), 1)
        req = _RecordingHandler.requests_received[0]
        self.assertEqual(req["body"]["event"], "deploy-finalized")
        self.assertEqual(req["headers"]["X-Custom"], "val")

    def test_custom_headers_sent(self):
        dest = {
            "name": "hdr-test",
            "url": f"http://127.0.0.1:{self.dest_port}/hook",
            "headers": {"Authorization": "Bearer tok123", "X-Source": "sm"},
            "events": [],
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        with patch.object(server, "LOG_FILE", ""), \
             patch.object(server, "MAX_RETRIES", 1):
            server.relay_to_destination(dest, SAMPLE_ENVELOPE, body, "req-002")

        req = _RecordingHandler.requests_received[0]
        self.assertEqual(req["headers"]["Authorization"], "Bearer tok123")
        self.assertEqual(req["headers"]["X-Source"], "sm")


class TestRelayRetry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _FailHandler.call_count = 0
        cls.fail_server = HTTPServer(("127.0.0.1", 0), _FailHandler)
        cls.fail_port = cls.fail_server.server_address[1]
        cls.fail_thread = threading.Thread(target=cls.fail_server.serve_forever, daemon=True)
        cls.fail_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.fail_server.shutdown()
        cls.fail_thread.join(timeout=5)

    def setUp(self):
        _FailHandler.call_count = 0

    def test_retries_on_500(self):
        dest = {
            "name": "fail-dest",
            "url": f"http://127.0.0.1:{self.fail_port}/hook",
            "headers": {},
            "events": [],
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        with patch.object(server, "LOG_FILE", ""), \
             patch.object(server, "MAX_RETRIES", 3), \
             patch.object(server, "INITIAL_BACKOFF", 0.01):
            server.relay_to_destination(dest, SAMPLE_ENVELOPE, body, "req-retry")

        self.assertEqual(_FailHandler.call_count, 3)

    def test_no_retry_on_4xx(self):
        _ForbiddenHandler.call_count = 0
        forbidden_server = HTTPServer(("127.0.0.1", 0), _ForbiddenHandler)
        forbidden_port = forbidden_server.server_address[1]
        forbidden_thread = threading.Thread(target=forbidden_server.serve_forever, daemon=True)
        forbidden_thread.start()
        try:
            dest = {
                "name": "forbidden-dest",
                "url": f"http://127.0.0.1:{forbidden_port}/hook",
                "headers": {},
                "events": [],
            }
            body = json.dumps(SAMPLE_ENVELOPE).encode()
            with patch.object(server, "LOG_FILE", ""), \
                 patch.object(server, "MAX_RETRIES", 3), \
                 patch.object(server, "INITIAL_BACKOFF", 0.01):
                server.relay_to_destination(dest, SAMPLE_ENVELOPE, body, "req-403")
            self.assertEqual(_ForbiddenHandler.call_count, 1)
        finally:
            forbidden_server.shutdown()
            forbidden_thread.join(timeout=5)

    def test_logs_failure_after_exhausting_retries(self):
        dest = {
            "name": "log-fail",
            "url": f"http://127.0.0.1:{self.fail_port}/hook",
            "headers": {},
            "events": [],
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            log_path = f.name
        try:
            with patch.object(server, "LOG_FILE", log_path), \
                 patch.object(server, "MAX_RETRIES", 2), \
                 patch.object(server, "INITIAL_BACKOFF", 0.01):
                server.relay_to_destination(dest, SAMPLE_ENVELOPE, body, "req-logfail")

            with open(log_path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertFalse(entry["ok"])
            self.assertEqual(entry["attempt"], 2)
            self.assertIn("error", entry)
        finally:
            os.unlink(log_path)


# ---------------------------------------------------------------------------
# Queue + worker pool tests
# ---------------------------------------------------------------------------
class TestDispatchQueue(unittest.TestCase):
    """Test that dispatch enqueues work items instead of blocking."""

    def test_dispatch_enqueues_matching_destinations(self):
        q = queue.Queue(maxsize=100)
        dest = {
            "name": "q-test",
            "url": "http://localhost:9999/hook",
            "events": ["deploy-finalized"],
            "headers": {},
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        with patch.object(server, "DESTINATIONS", [dest]), \
             patch.object(server, "_work_queue", q):
            count = server.dispatch(SAMPLE_ENVELOPE, body, "req-q1")

        self.assertEqual(count, 1)
        self.assertEqual(q.qsize(), 1)
        item = q.get_nowait()
        self.assertEqual(item[0]["name"], "q-test")

    def test_dispatch_skips_non_matching_events(self):
        q = queue.Queue(maxsize=100)
        dest = {
            "name": "q-skip",
            "url": "http://localhost:9999/hook",
            "events": ["post-instance-create"],
            "headers": {},
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        with patch.object(server, "DESTINATIONS", [dest]), \
             patch.object(server, "_work_queue", q):
            count = server.dispatch(SAMPLE_ENVELOPE, body, "req-q2")

        self.assertEqual(count, 0)
        self.assertTrue(q.empty())

    def test_dispatch_empty_events_matches_all(self):
        q = queue.Queue(maxsize=100)
        dest = {
            "name": "q-all",
            "url": "http://localhost:9999/hook",
            "events": [],
            "headers": {},
        }
        env = {**SAMPLE_ENVELOPE, "event": "post-instance-delete"}
        body = json.dumps(env).encode()
        with patch.object(server, "DESTINATIONS", [dest]), \
             patch.object(server, "_work_queue", q):
            count = server.dispatch(env, body, "req-q3")

        self.assertEqual(count, 1)

    def test_dispatch_drops_when_queue_full(self):
        q = queue.Queue(maxsize=1)
        q.put("filler")
        dest = {
            "name": "q-full",
            "url": "http://localhost:9999/hook",
            "events": [],
            "headers": {},
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        original_dropped = server.get_dropped_count()
        with patch.object(server, "DESTINATIONS", [dest]), \
             patch.object(server, "_work_queue", q):
            count = server.dispatch(SAMPLE_ENVELOPE, body, "req-q4")

        self.assertEqual(count, 0)
        self.assertGreater(server.get_dropped_count(), original_dropped)


class TestWorkerPool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _RecordingHandler.requests_received = []
        _RecordingHandler.respond_status = 200
        cls.dest_server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
        cls.dest_port = cls.dest_server.server_address[1]
        cls.dest_thread = threading.Thread(target=cls.dest_server.serve_forever, daemon=True)
        cls.dest_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.dest_server.shutdown()
        cls.dest_thread.join(timeout=5)

    def setUp(self):
        _RecordingHandler.requests_received = []

    def test_worker_processes_queue_item(self):
        q = queue.Queue(maxsize=100)
        dest = {
            "name": "w-test",
            "url": f"http://127.0.0.1:{self.dest_port}/hook",
            "headers": {},
            "events": [],
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        q.put((dest, SAMPLE_ENVELOPE, body, "req-w1"))
        q.put(None)

        with patch.object(server, "_work_queue", q), \
             patch.object(server, "LOG_FILE", ""), \
             patch.object(server, "MAX_RETRIES", 1):
            server._worker()

        self.assertEqual(len(_RecordingHandler.requests_received), 1)
        self.assertEqual(_RecordingHandler.requests_received[0]["body"]["event"], "deploy-finalized")

    def test_worker_survives_exception(self):
        q = queue.Queue(maxsize=100)
        dest = {
            "name": "w-err",
            "url": "http://127.0.0.1:1/never",
            "headers": {},
            "events": [],
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        q.put((dest, SAMPLE_ENVELOPE, body, "req-w2"))
        q.put(None)

        with patch.object(server, "_work_queue", q), \
             patch.object(server, "LOG_FILE", ""), \
             patch.object(server, "MAX_RETRIES", 1), \
             patch.object(server, "REQUEST_TIMEOUT", 1):
            server._worker()

        self.assertTrue(q.empty())

    def test_start_and_stop_workers(self):
        old_workers = server._workers.copy()
        server._workers.clear()

        q = queue.Queue(maxsize=100)
        with patch.object(server, "_work_queue", q):
            server.start_workers(count=3)
            self.assertEqual(len(server._workers), 3)
            for t in server._workers:
                self.assertTrue(t.is_alive())
            server.stop_workers()

        self.assertEqual(len(server._workers), 0)
        server._workers.extend(old_workers)

    def test_end_to_end_dispatch_through_workers(self):
        """Dispatch enqueues, workers pick up and deliver to the real destination."""
        q = queue.Queue(maxsize=100)
        dest = {
            "name": "e2e",
            "url": f"http://127.0.0.1:{self.dest_port}/hook",
            "events": ["deploy-finalized"],
            "headers": {"X-E2E": "yes"},
        }
        body = json.dumps(SAMPLE_ENVELOPE).encode()

        old_workers = server._workers.copy()
        server._workers.clear()

        with patch.object(server, "_work_queue", q), \
             patch.object(server, "DESTINATIONS", [dest]), \
             patch.object(server, "LOG_FILE", ""), \
             patch.object(server, "MAX_RETRIES", 1):
            server.start_workers(count=2)
            server.dispatch(SAMPLE_ENVELOPE, body, "req-e2e")
            q.join()
            server.stop_workers()

        server._workers.extend(old_workers)

        self.assertEqual(len(_RecordingHandler.requests_received), 1)
        self.assertEqual(_RecordingHandler.requests_received[0]["headers"]["X-E2E"], "yes")


# ---------------------------------------------------------------------------
# HTTP handler integration tests
# ---------------------------------------------------------------------------
class TestHTTPHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), server.HookHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
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
        self.assertIn("destinations", body)
        self.assertIn("queue_depth", body)
        self.assertIn("dropped", body)
        conn.close()

    def test_get_unknown_returns_404(self):
        conn = self._conn()
        conn.request("GET", "/nope")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 404)
        conn.close()

    def test_post_invalid_json_returns_400(self):
        conn = self._conn()
        conn.request("POST", "/hook", body=b"{{bad", headers={"Content-Length": "5"})
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

    @patch.object(server, "dispatch")
    def test_post_valid_envelope_returns_allowed(self, mock_dispatch):
        mock_dispatch.return_value = 0
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
            self.assertTrue(data["allowed"])
            conn.close()
        mock_dispatch.assert_called_once()

    @patch.object(server, "dispatch")
    def test_post_with_valid_hmac(self, mock_dispatch):
        mock_dispatch.return_value = 0
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
        mock_dispatch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
