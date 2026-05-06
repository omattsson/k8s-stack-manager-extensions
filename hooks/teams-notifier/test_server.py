#!/usr/bin/env python3
import hashlib
import hmac
import http.client
import json
import queue
import threading
import time
import unittest
from http.server import HTTPServer
from unittest.mock import patch, MagicMock

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
        with patch.object(server, "_card_template", None):
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
        self.assertEqual(actions[0]["title"], "Open site")
        self.assertEqual(actions[1]["title"], "Stack Manager")
        self.assertIn("inst-001", actions[1]["url"])

    def test_failure_card(self):
        env = {**SAMPLE_ENVELOPE, "instance": {**SAMPLE_ENVELOPE["instance"], "status": "error"}}
        with patch.object(server, "_card_template", None):
            card = server.build_adaptive_card(env)
        heading = card["attachments"][0]["content"]["body"][0]
        self.assertIn("failed", heading["text"])
        self.assertEqual(heading["color"], "attention")

    def test_no_cluster_omits_fact(self):
        env = {**SAMPLE_ENVELOPE, "instance": {**SAMPLE_ENVELOPE["instance"], "cluster_id": ""}}
        with patch.object(server, "_card_template", None):
            card = server.build_adaptive_card(env)
        facts = card["attachments"][0]["content"]["body"][1]["facts"]
        fact_titles = [f["title"] for f in facts]
        self.assertNotIn("Cluster", fact_titles)

    def test_missing_instance_uses_defaults(self):
        with patch.object(server, "_card_template", None):
            card = server.build_adaptive_card({"event": "deploy-finalized"})
        heading = card["attachments"][0]["content"]["body"][0]
        self.assertIn("unknown", heading["text"])

    def test_custom_stack_manager_url(self):
        with patch.object(server, "STACK_MANAGER_URL", "https://my.host"), \
             patch.object(server, "_card_template", None):
            card = server.build_adaptive_card(SAMPLE_ENVELOPE)
            sm_action = card["attachments"][0]["content"]["actions"][1]
            self.assertTrue(sm_action["url"].startswith("https://my.host/"))


class TestSiteDomain(unittest.TestCase):
    def test_fallback_card_uses_site_domain(self):
        with patch.object(server, "SITE_DOMAIN", "klaravik.test"), \
             patch.object(server, "_card_template", None):
            card = server.build_adaptive_card(SAMPLE_ENVELOPE)
            site_action = card["attachments"][0]["content"]["actions"][0]
            self.assertEqual(site_action["url"], "https://demo.klaravik.test")

    def test_fallback_card_default_domain(self):
        with patch.object(server, "SITE_DOMAIN", "localhost"), \
             patch.object(server, "_card_template", None):
            card = server.build_adaptive_card(SAMPLE_ENVELOPE)
            site_action = card["attachments"][0]["content"]["actions"][0]
            self.assertEqual(site_action["url"], "https://demo.localhost")


class TestBuildTemplateVariables(unittest.TestCase):
    def test_all_keys_present(self):
        with patch.object(server, "SITE_DOMAIN", "klaravik.test"), \
             patch.object(server, "STACK_MANAGER_URL", "https://sm.example"):
            variables = server.build_template_variables(SAMPLE_ENVELOPE)
        expected_keys = {
            "name", "namespace", "branch", "cluster_id", "status",
            "instance_id", "emoji", "outcome", "color",
            "instance_url", "site_url", "site_domain", "stack_manager_url",
        }
        self.assertEqual(set(variables.keys()), expected_keys)

    def test_success_variables(self):
        with patch.object(server, "SITE_DOMAIN", "dev.local"), \
             patch.object(server, "STACK_MANAGER_URL", "https://sm"):
            v = server.build_template_variables(SAMPLE_ENVELOPE)
        self.assertEqual(v["name"], "demo")
        self.assertEqual(v["emoji"], "✅")
        self.assertEqual(v["outcome"], "succeeded")
        self.assertEqual(v["color"], "good")
        self.assertEqual(v["site_url"], "https://demo.dev.local")
        self.assertEqual(v["site_domain"], "dev.local")
        self.assertEqual(v["instance_url"], "https://sm/stack-instances/inst-001")

    def test_failure_variables(self):
        env = {**SAMPLE_ENVELOPE, "instance": {**SAMPLE_ENVELOPE["instance"], "status": "error"}}
        with patch.object(server, "SITE_DOMAIN", "x"), \
             patch.object(server, "STACK_MANAGER_URL", "https://sm"):
            v = server.build_template_variables(env)
        self.assertEqual(v["emoji"], "❌")
        self.assertEqual(v["outcome"], "failed")
        self.assertEqual(v["color"], "attention")


class TestRenderTemplate(unittest.TestCase):
    def test_simple_substitution(self):
        template = '{"title": "{{name}} on {{site_domain}}"}'
        result = server.render_template(template, {"name": "demo", "site_domain": "klaravik.test"})
        self.assertEqual(result["title"], "demo on klaravik.test")

    def test_unknown_placeholder_kept(self):
        template = '{"title": "{{unknown}}"}'
        result = server.render_template(template, {"name": "demo"})
        self.assertEqual(result["title"], "{{unknown}}")

    def test_full_card_template(self):
        template = json.dumps({
            "type": "message",
            "attachments": [{
                "content": {
                    "body": [{"text": "{{emoji}} Deploy {{outcome}} — {{name}}"}],
                    "actions": [
                        {"type": "Action.OpenUrl", "url": "https://{{name}}.{{site_domain}}"},
                        {"type": "Action.OpenUrl", "url": "{{instance_url}}"},
                    ],
                },
            }],
        })
        variables = {
            "name": "olofm",
            "site_domain": "klaravik.test",
            "emoji": "✅",
            "outcome": "succeeded",
            "instance_url": "https://sm/stack-instances/abc",
        }
        result = server.render_template(template, variables)
        self.assertEqual(result["attachments"][0]["content"]["actions"][0]["url"], "https://olofm.klaravik.test")
        self.assertIn("succeeded", result["attachments"][0]["content"]["body"][0]["text"])


class TestCardTemplateIntegration(unittest.TestCase):
    def test_template_path_used_when_set(self):
        template = json.dumps({
            "type": "message",
            "text": "{{name}} deployed to {{site_domain}}",
        })
        with patch.object(server, "_card_template", template), \
             patch.object(server, "SITE_DOMAIN", "klaravik.test"), \
             patch.object(server, "STACK_MANAGER_URL", "https://sm"):
            card = server.build_adaptive_card(SAMPLE_ENVELOPE)
        self.assertEqual(card["text"], "demo deployed to klaravik.test")

    def test_fallback_when_no_template(self):
        with patch.object(server, "_card_template", None), \
             patch.object(server, "SITE_DOMAIN", "localhost"):
            card = server.build_adaptive_card(SAMPLE_ENVELOPE)
        self.assertEqual(card["type"], "message")
        self.assertIn("attachments", card)


class TestLoadCardTemplate(unittest.TestCase):
    def test_empty_path_returns_none(self):
        with patch.object(server, "CARD_TEMPLATE_FILE", ""):
            self.assertIsNone(server.load_card_template())

    def test_missing_file_returns_none(self):
        with patch.object(server, "CARD_TEMPLATE_FILE", "/nonexistent/card.json"):
            self.assertIsNone(server.load_card_template())

    def test_existing_file_returns_content(self):
        import tempfile, os
        content = '{"type": "message", "text": "{{name}}"}'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            f.flush()
            path = f.name
        try:
            with patch.object(server, "CARD_TEMPLATE_FILE", path):
                result = server.load_card_template()
            self.assertEqual(result, content)
        finally:
            os.unlink(path)


class TestEnqueueCard(unittest.TestCase):
    def test_enqueue_returns_true(self):
        q = queue.Queue(maxsize=10)
        with patch.object(server, "_work_queue", q):
            self.assertTrue(server.enqueue_card({"type": "message"}))
        self.assertEqual(q.qsize(), 1)

    def test_enqueue_full_queue_returns_false(self):
        q = queue.Queue(maxsize=1)
        q.put("filler")
        with patch.object(server, "_work_queue", q):
            self.assertFalse(server.enqueue_card({"type": "message"}))

    def test_dropped_counter_increments(self):
        q = queue.Queue(maxsize=1)
        q.put("filler")
        original_dropped = server.get_dropped_count()
        with patch.object(server, "_work_queue", q):
            server.enqueue_card({"type": "message"})
        self.assertEqual(server.get_dropped_count(), original_dropped + 1)


class TestWorkerPool(unittest.TestCase):
    def test_worker_processes_queued_item(self):
        delivered = []
        q = queue.Queue(maxsize=10)
        card = {"type": "message", "test": True}
        q.put(card)
        q.put(None)

        with patch.object(server, "_work_queue", q), \
             patch.object(server, "post_to_teams", side_effect=lambda c: delivered.append(c)):
            server._worker()

        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0]["test"], True)

    def test_worker_handles_exception(self):
        q = queue.Queue(maxsize=10)
        q.put({"type": "message"})
        q.put(None)

        with patch.object(server, "_work_queue", q), \
             patch.object(server, "post_to_teams", side_effect=RuntimeError("boom")):
            server._worker()

        self.assertTrue(q.empty())

    def test_start_and_stop_workers(self):
        old_workers = server._workers.copy()
        server._workers.clear()

        q = queue.Queue(maxsize=100)
        with patch.object(server, "_work_queue", q):
            server.start_workers(count=2)
            self.assertEqual(len(server._workers), 2)
            for t in server._workers:
                self.assertTrue(t.is_alive())
            server.stop_workers()

        self.assertEqual(len(server._workers), 0)
        server._workers.extend(old_workers)


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
        self.assertIn("queue_depth", body)
        self.assertIn("dropped", body)
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

    @patch.object(server, "enqueue_card")
    @patch.object(server, "TEAMS_WEBHOOK_URL", "https://fake.teams/webhook")
    def test_deploy_finalized_enqueues_card(self, mock_enqueue):
        mock_enqueue.return_value = True
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
        mock_enqueue.assert_called_once()
        card = mock_enqueue.call_args[0][0]
        self.assertEqual(card["type"], "message")

    @patch.object(server, "enqueue_card")
    @patch.object(server, "TEAMS_WEBHOOK_URL", "https://fake.teams/webhook")
    def test_non_deploy_event_does_not_enqueue(self, mock_enqueue):
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
        mock_enqueue.assert_not_called()

    @patch.object(server, "enqueue_card")
    @patch.object(server, "TEAMS_WEBHOOK_URL", "")
    def test_no_webhook_url_skips_enqueue(self, mock_enqueue):
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
        mock_enqueue.assert_not_called()

    def test_post_with_valid_hmac_succeeds(self):
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        sig = _sign(body)
        with patch.object(server, "SECRET", TEST_SECRET), \
             patch.object(server, "TEAMS_WEBHOOK_URL", ""), \
             patch.object(server, "enqueue_card"):
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
