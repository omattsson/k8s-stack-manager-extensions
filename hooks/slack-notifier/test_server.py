#!/usr/bin/env python3
import hashlib
import hmac
import http.client
import json
import threading
import unittest
from http.server import HTTPServer
from unittest.mock import patch

import server

SAMPLE_ENVELOPE = {
    "apiVersion": "hooks.k8sstackmanager.io/v1",
    "kind": "EventEnvelope",
    "event": "deploy-finalized",
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


class TestBuildSlackBlocks(unittest.TestCase):
    def test_success_message(self):
        payload = server.build_slack_blocks(SAMPLE_ENVELOPE)
        text = payload["blocks"][0]["text"]["text"]
        self.assertIn("succeeded", text)
        self.assertIn("demo", text)

    def test_failure_message(self):
        env = {**SAMPLE_ENVELOPE, "instance": {**SAMPLE_ENVELOPE["instance"], "status": "error"}}
        payload = server.build_slack_blocks(env)
        text = payload["blocks"][0]["text"]["text"]
        self.assertIn("failed", text)


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

    @patch.object(server, "post_to_slack")
    @patch.object(server, "SLACK_WEBHOOK_URL", "https://fake.slack/webhook")
    def test_deploy_finalized_posts_to_slack(self, mock_post):
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
        mock_post.assert_called_once()

    @patch.object(server, "post_to_slack")
    @patch.object(server, "SLACK_WEBHOOK_URL", "https://fake.slack/webhook")
    def test_non_deploy_event_does_not_post(self, mock_post):
        env = {**SAMPLE_ENVELOPE, "event": "post-instance-create"}
        body = json.dumps(env).encode()
        with patch.object(server, "SECRET", ""):
            conn = self._conn()
            conn.request(
                "POST", "/hook", body=body,
                headers={"Content-Length": str(len(body))},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            conn.close()
        mock_post.assert_not_called()

    def test_post_with_valid_hmac(self):
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        sig = _sign(body)
        with patch.object(server, "SECRET", TEST_SECRET), \
             patch.object(server, "SLACK_WEBHOOK_URL", ""), \
             patch.object(server, "post_to_slack"):
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


if __name__ == "__main__":
    unittest.main()
