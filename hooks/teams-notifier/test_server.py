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


class TestVerifySignature(unittest.TestCase):
    def test_valid_signature(self):
        body = b'{"event":"test"}'
        sig = _sign(body)
        with patch.object(server, "SECRET", TEST_SECRET):
            self.assertTrue(server.verify_signature(body, sig))

    def test_invalid_signature(self):
        body = b'{"event":"test"}'
        with patch.object(server, "SECRET", TEST_SECRET):
            self.assertFalse(server.verify_signature(body, "sha256=bad"))

    def test_empty_secret_skips_verification(self):
        with patch.object(server, "SECRET", ""):
            self.assertTrue(server.verify_signature(b"anything", ""))


class TestBuildAdaptiveCard(unittest.TestCase):
    def test_success_card(self):
        card = server.build_adaptive_card(SAMPLE_ENVELOPE)
        self.assertEqual(card["type"], "message")
        attachments = card["attachments"]
        self.assertEqual(len(attachments), 1)
        content = attachments[0]["content"]
        self.assertEqual(content["type"], "AdaptiveCard")
        self.assertEqual(content["version"], "1.4")

        body_blocks = content["body"]
        heading = body_blocks[0]
        self.assertIn("succeeded", heading["text"])
        self.assertIn("demo", heading["text"])
        self.assertEqual(heading["color"], "good")

        facts = body_blocks[1]["facts"]
        fact_titles = [f["title"] for f in facts]
        self.assertIn("Namespace", fact_titles)
        self.assertIn("Branch", fact_titles)
        self.assertIn("Cluster", fact_titles)

        actions = content["actions"]
        self.assertEqual(actions[0]["type"], "Action.OpenUrl")
        self.assertIn("inst-001", actions[0]["url"])

    def test_failure_card(self):
        env = {**SAMPLE_ENVELOPE, "instance": {**SAMPLE_ENVELOPE["instance"], "status": "error"}}
        card = server.build_adaptive_card(env)
        heading = card["attachments"][0]["content"]["body"][0]
        self.assertIn("failed", heading["text"])
        self.assertEqual(heading["color"], "attention")

    def test_no_cluster_omits_fact(self):
        env = {**SAMPLE_ENVELOPE, "instance": {**SAMPLE_ENVELOPE["instance"], "cluster_id": ""}}
        card = server.build_adaptive_card(env)
        facts = card["attachments"][0]["content"]["body"][1]["facts"]
        fact_titles = [f["title"] for f in facts]
        self.assertNotIn("Cluster", fact_titles)

    def test_missing_instance_uses_defaults(self):
        card = server.build_adaptive_card({"event": "deploy-finalized"})
        heading = card["attachments"][0]["content"]["body"][0]
        self.assertIn("unknown", heading["text"])

    def test_custom_stack_manager_url(self):
        with patch.object(server, "STACK_MANAGER_URL", "https://my.host"):
            card = server.build_adaptive_card(SAMPLE_ENVELOPE)
            url = card["attachments"][0]["content"]["actions"][0]["url"]
            self.assertTrue(url.startswith("https://my.host/"))


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

    def test_get_unknown_path_returns_404(self):
        conn = self._conn()
        conn.request("GET", "/unknown")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 404)
        conn.close()

    def test_post_invalid_json_returns_400(self):
        conn = self._conn()
        conn.request("POST", "/hook", body=b"not json", headers={"Content-Length": "8"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        conn.close()

    def test_post_invalid_signature_returns_401(self):
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

    @patch.object(server, "post_to_teams")
    @patch.object(server, "TEAMS_WEBHOOK_URL", "https://fake.teams/webhook")
    def test_deploy_finalized_posts_to_teams(self, mock_post):
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
        card = mock_post.call_args[0][0]
        self.assertEqual(card["type"], "message")

    @patch.object(server, "post_to_teams")
    @patch.object(server, "TEAMS_WEBHOOK_URL", "https://fake.teams/webhook")
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

    @patch.object(server, "post_to_teams")
    @patch.object(server, "TEAMS_WEBHOOK_URL", "")
    def test_no_webhook_url_skips_post(self, mock_post):
        body = json.dumps(SAMPLE_ENVELOPE).encode()
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

    def test_post_with_valid_hmac_succeeds(self):
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        sig = _sign(body)
        with patch.object(server, "SECRET", TEST_SECRET), \
             patch.object(server, "TEAMS_WEBHOOK_URL", ""), \
             patch.object(server, "post_to_teams"):
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
