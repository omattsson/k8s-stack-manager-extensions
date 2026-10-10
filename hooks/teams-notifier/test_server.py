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
        with patch.object(server, "SITE_DOMAIN", "example.test"), \
             patch.object(server, "_card_template", None):
            card = server.build_adaptive_card(SAMPLE_ENVELOPE)
            site_action = card["attachments"][0]["content"]["actions"][0]
            self.assertEqual(site_action["url"], "https://demo.example.test")

    def test_fallback_card_default_domain(self):
        with patch.object(server, "SITE_DOMAIN", "localhost"), \
             patch.object(server, "_card_template", None):
            card = server.build_adaptive_card(SAMPLE_ENVELOPE)
            site_action = card["attachments"][0]["content"]["actions"][0]
            self.assertEqual(site_action["url"], "https://demo.localhost")


class TestBuildTemplateVariables(unittest.TestCase):
    def test_all_keys_present(self):
        with patch.object(server, "SITE_DOMAIN", "example.test"), \
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
        result = server.render_template(template, {"name": "demo", "site_domain": "example.test"})
        self.assertEqual(result["title"], "demo on example.test")

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
            "name": "alice",
            "site_domain": "example.test",
            "emoji": "✅",
            "outcome": "succeeded",
            "instance_url": "https://sm/stack-instances/abc",
        }
        result = server.render_template(template, variables)
        self.assertEqual(result["attachments"][0]["content"]["actions"][0]["url"], "https://alice.example.test")
        self.assertIn("succeeded", result["attachments"][0]["content"]["body"][0]["text"])


class TestCardTemplateIntegration(unittest.TestCase):
    def test_template_path_used_when_set(self):
        template = json.dumps({
            "type": "message",
            "text": "{{name}} deployed to {{site_domain}}",
        })
        with patch.object(server, "_card_template", template), \
             patch.object(server, "SITE_DOMAIN", "example.test"), \
             patch.object(server, "STACK_MANAGER_URL", "https://sm"):
            card = server.build_adaptive_card(SAMPLE_ENVELOPE)
        self.assertEqual(card["text"], "demo deployed to example.test")

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


SAMPLE_NOTIFICATION = {
    "event_type": "deployment.success",
    "timestamp": "2026-05-10T12:00:00Z",
    "title": "Deployment succeeded",
    "message": "my-stack deployed to production cluster",
    "user_display_name": "Olof Mattsson",
    "entity_type": "stack_instance",
    "entity_id": "inst-001",
}


class TestBuildNotificationCard(unittest.TestCase):
    def test_basic_card_structure(self):
        card = server.build_notification_card(SAMPLE_NOTIFICATION)
        self.assertEqual(card["type"], "message")
        attachments = card["attachments"]
        self.assertEqual(len(attachments), 1)
        content = attachments[0]["content"]
        self.assertEqual(content["type"], "AdaptiveCard")
        self.assertEqual(content["version"], "1.4")

    def test_heading_includes_user(self):
        card = server.build_notification_card(SAMPLE_NOTIFICATION)
        body = card["attachments"][0]["content"]["body"]
        heading = body[0]["text"]
        self.assertIn("Deployment succeeded", heading)
        self.assertIn("Olof Mattsson", heading)

    def test_heading_omits_system_user(self):
        payload = {**SAMPLE_NOTIFICATION, "user_display_name": "System"}
        card = server.build_notification_card(payload)
        heading = card["attachments"][0]["content"]["body"][0]["text"]
        self.assertNotIn("System", heading)

    def test_success_color(self):
        card = server.build_notification_card(SAMPLE_NOTIFICATION)
        color = card["attachments"][0]["content"]["body"][0]["color"]
        self.assertEqual(color, "good")

    def test_error_color(self):
        payload = {**SAMPLE_NOTIFICATION, "event_type": "deployment.error", "title": "Deploy failed"}
        card = server.build_notification_card(payload)
        color = card["attachments"][0]["content"]["body"][0]["color"]
        self.assertEqual(color, "attention")

    def test_warning_color(self):
        payload = {**SAMPLE_NOTIFICATION, "event_type": "stack.expiring", "title": "Stack expiring"}
        card = server.build_notification_card(payload)
        color = card["attachments"][0]["content"]["body"][0]["color"]
        self.assertEqual(color, "warning")

    def test_entity_link_action(self):
        card = server.build_notification_card(SAMPLE_NOTIFICATION)
        actions = card["attachments"][0]["content"]["actions"]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["type"], "Action.OpenUrl")
        self.assertIn("stack-instances/inst-001", actions[0]["url"])

    def test_no_actions_without_entity(self):
        payload = {**SAMPLE_NOTIFICATION, "entity_type": "", "entity_id": ""}
        card = server.build_notification_card(payload)
        actions = card["attachments"][0]["content"]["actions"]
        self.assertEqual(len(actions), 0)

    def test_message_in_body(self):
        card = server.build_notification_card(SAMPLE_NOTIFICATION)
        body = card["attachments"][0]["content"]["body"]
        texts = [b["text"] for b in body if b["type"] == "TextBlock"]
        self.assertTrue(any("my-stack deployed" in t for t in texts))

    def test_facts_include_event_and_user(self):
        card = server.build_notification_card(SAMPLE_NOTIFICATION)
        body = card["attachments"][0]["content"]["body"]
        factsets = [b for b in body if b["type"] == "FactSet"]
        self.assertEqual(len(factsets), 1)
        fact_titles = [f["title"] for f in factsets[0]["facts"]]
        self.assertIn("Event", fact_titles)
        self.assertIn("User", fact_titles)


class TestNotificationCardTemplate(unittest.TestCase):
    def test_template_rendering_with_notification_payload(self):
        template = '{"text": "{{event_type}}: {{title}} by {{user_display_name}}"}'
        old = server._card_template
        try:
            server._card_template = template
            card = server.build_notification_card(SAMPLE_NOTIFICATION)
            self.assertEqual(card["text"], "deployment.success: Deployment succeeded by Olof Mattsson")
        finally:
            server._card_template = old

    def test_template_casts_none_to_empty_string(self):
        template = '{"text": "{{entity_type}}/{{entity_id}}"}'
        payload = {**SAMPLE_NOTIFICATION, "entity_type": None, "entity_id": None}
        old = server._card_template
        try:
            server._card_template = template
            card = server.build_notification_card(payload)
            self.assertEqual(card["text"], "/")
        finally:
            server._card_template = old


class TestHTTPHandlerNotificationPayload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._old_webhook = server.TEAMS_WEBHOOK_URL
        cls._old_secret = server.SECRET
        server.TEAMS_WEBHOOK_URL = "http://localhost:1/fake"
        server.SECRET = ""
        cls.httpd = HTTPServer(("127.0.0.1", 0), server.HookHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.thread.join(timeout=5)
        cls.httpd.server_close()
        server.TEAMS_WEBHOOK_URL = cls._old_webhook
        server.SECRET = cls._old_secret

    def test_notification_payload_enqueues_card(self):
        body = json.dumps(SAMPLE_NOTIFICATION).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/hook", body, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        data = json.loads(resp.read())
        self.assertTrue(data.get("allowed", False))
        conn.close()

    def test_hook_payload_still_works(self):
        body = json.dumps(SAMPLE_ENVELOPE).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/hook", body, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        conn.close()



def _event_envelope(event, status="stopped", trigger=None, metadata=None):
    env = {
        **SAMPLE_ENVELOPE,
        "event": event,
        "instance": {**SAMPLE_ENVELOPE["instance"], "status": status},
    }
    if trigger is not None:
        env["trigger"] = trigger
    if metadata is not None:
        env["metadata"] = metadata
    return env


def _card_texts(card):
    content = card["attachments"][0]["content"]
    texts = [b.get("text", "") for b in content["body"] if b["type"] == "TextBlock"]
    facts = {}
    for b in content["body"]:
        if b["type"] == "FactSet":
            facts.update({f["title"]: f["value"] for f in b["facts"]})
    return texts, facts, content["actions"]


POLICY_TRIGGER = {"type": "cleanup-policy", "id": "pol-1", "name": "nightly-stop"}

SAMPLE_POLICY_RUN = {
    "apiVersion": "hooks.k8sstackmanager.io/v1",
    "kind": "EventEnvelope",
    "event": "cleanup-policy-executed",
    "request_id": "req-pol",
    "trigger": POLICY_TRIGGER,
    "cleanup_policy": {
        "id": "pol-1",
        "name": "nightly-stop",
        "action": "stop",
        "cluster_id": "all",
        "condition": "idle_days:3",
        "dry_run": False,
        "run": "scheduled",
        "matched": 2,
        "succeeded": 1,
        "failed": 1,
        "instances": [
            {"id": "i1", "name": "demo", "namespace": "stack-demo", "owner_id": "u1", "result": "success"},
            {"id": "i2", "name": "old", "namespace": "stack-old", "owner_id": "u2", "result": "error", "error": "cluster unreachable"},
        ],
    },
}


class TestEventCards(unittest.TestCase):
    def test_titles_per_event(self):
        cases = [
            ("stop-completed", "stopped", None, "⏹ Stack stopped — demo"),
            ("stop-completed", "error", None, "❌ Stop failed — demo"),
            ("clean-completed", "draft", None, "🧹 Stack cleaned — demo"),
            ("clean-completed", "error", None, "❌ Clean failed — demo"),
            ("delete-completed", "draft", None, "🗑 Stack deleted — demo"),
            ("deploy-timeout", "error", None, "⏱ Deploy timed out — demo"),
            ("rollback-completed", "running", {"outcome": "succeeded"}, "↩ Rollback succeeded — demo"),
            ("rollback-completed", "error", {"outcome": "failed"}, "❌ Rollback failed — demo"),
            ("rollback-completed", "running", {"outcome": "rejected"}, "⛔ Rollback rejected — demo"),
            ("rollback-completed", "stopped", {"outcome": "cancelled"}, "⚠️ Rollback cancelled — demo"),
        ]
        for event, status, metadata, title in cases:
            with self.subTest(event=event, status=status, metadata=metadata), \
                 patch.object(server, "TEAMS_EVENTS", server.KNOWN_TEAMS_EVENTS):
                card = server.build_hook_card(_event_envelope(event, status, metadata=metadata))
                texts, facts, _ = _card_texts(card)
                self.assertEqual(texts[0], title)
                self.assertEqual(facts["Namespace"], "stack-demo-alice")
                self.assertEqual(facts["Cluster"], "dev")

    def test_policy_trigger_is_named(self):
        with patch.object(server, "TEAMS_POLICY_INSTANCE_CARDS", True):
            card = server.build_hook_card(_event_envelope("stop-completed", trigger=POLICY_TRIGGER))
        texts, facts, _ = _card_texts(card)
        self.assertIn("Stack stopped by cleanup policy nightly-stop", texts)
        self.assertEqual(facts["Triggered by"], "cleanup policy nightly-stop")

    def test_policy_instance_cards_skipped_by_default(self):
        for event, status in (("stop-completed", "stopped"), ("clean-completed", "draft"), ("delete-completed", "draft")):
            with self.subTest(event=event):
                env = _event_envelope(event, status, trigger=POLICY_TRIGGER)
                self.assertIsNone(server.build_hook_card(env))
                self.assertEqual(server.skip_reason(env), "covered by the cleanup-policy-executed card")

    def test_failed_policy_operation_keeps_card(self):
        env = _event_envelope("stop-completed", "error", trigger=POLICY_TRIGGER)
        texts, _, _ = _card_texts(server.build_hook_card(env))
        self.assertEqual(texts[0], "❌ Stop failed — demo")

    def test_user_stop_keeps_card(self):
        env = _event_envelope("stop-completed", trigger={"type": "user", "name": "alice"})
        self.assertIsNotNone(server.build_hook_card(env))

    def test_trigger_texts(self):
        cases = [
            ({"type": "user", "id": "u1", "name": "alice"}, "alice"),
            ({"type": "user"}, "a user"),
            ({"type": "ttl"}, "TTL expiry"),
            (POLICY_TRIGGER, "cleanup policy nightly-stop"),
            (None, ""),
        ]
        for trigger, want in cases:
            with self.subTest(trigger=trigger):
                env = _event_envelope("clean-completed", trigger=trigger)
                self.assertEqual(server.trigger_text(env), want)

    def test_no_trigger_has_no_trigger_fact(self):
        card = server.build_hook_card(_event_envelope("stop-completed"))
        _, facts, _ = _card_texts(card)
        self.assertNotIn("Triggered by", facts)

    def test_delete_card_has_no_stack_link(self):
        card = server.build_hook_card(_event_envelope("delete-completed", "draft"))
        _, _, actions = _card_texts(card)
        self.assertEqual(actions, [])

    def test_stop_card_links_to_stack(self):
        with patch.object(server, "STACK_MANAGER_URL", "https://sm.example"):
            card = server.build_hook_card(_event_envelope("stop-completed"))
        _, _, actions = _card_texts(card)
        self.assertEqual(actions[0]["url"], "https://sm.example/stack-instances/inst-001")

    def test_deploy_finalized_card_unchanged(self):
        self.assertEqual(server.build_hook_card(SAMPLE_ENVELOPE), server.build_adaptive_card(SAMPLE_ENVELOPE))

    def test_clean_of_delete_has_no_card(self):
        env = _event_envelope("clean-completed", "draft", metadata={"operation": "delete"})
        self.assertIsNone(server.build_hook_card(env))

    def test_failed_clean_of_delete_keeps_card(self):
        env = _event_envelope("clean-completed", "error", metadata={"operation": "delete"})
        texts, _, _ = _card_texts(server.build_hook_card(env))
        self.assertEqual(texts[0], "❌ Clean failed — demo")

    def test_unknown_event_has_no_card(self):
        self.assertIsNone(server.build_hook_card(_event_envelope("post-instance-create")))


class TestPolicyCard(unittest.TestCase):
    def test_summary_card(self):
        card = server.build_hook_card(SAMPLE_POLICY_RUN)
        texts, facts, actions = _card_texts(card)
        self.assertEqual(texts[0], "🧹 Cleanup policy nightly-stop: stop on 2 stack(s)")
        self.assertIn("- demo: success", texts[1])
        self.assertIn("- old: error — cluster unreachable", texts[1])
        self.assertEqual(facts["Condition"], "idle_days:3")
        self.assertEqual(facts["Failed"], "1")
        self.assertEqual(card["attachments"][0]["content"]["body"][0]["color"], "attention")
        self.assertTrue(actions[0]["url"].endswith("/admin/cleanup-policies"))

    def test_dry_run_title(self):
        env = json.loads(json.dumps(SAMPLE_POLICY_RUN))
        env["cleanup_policy"]["dry_run"] = True
        texts, _, _ = _card_texts(server.build_hook_card(env))
        self.assertTrue(texts[0].endswith("(dry run)"))

    def test_long_list_is_cut(self):
        env = json.loads(json.dumps(SAMPLE_POLICY_RUN))
        env["cleanup_policy"]["instances"] = [
            {"id": f"i{n}", "name": f"s{n}", "result": "success"} for n in range(25)
        ]
        env["cleanup_policy"]["matched"] = 30
        texts, _, _ = _card_texts(server.build_hook_card(env))
        self.assertEqual(texts[1].count("\n- s"), server.MAX_POLICY_LINES - 1)
        self.assertTrue(texts[1].endswith("- and 10 more"))


class TestMarkdownEscape(unittest.TestCase):
    def test_escapes_markdown(self):
        cases = [
            ("plain-name.v2", "plain-name.v2"),
            ("feature/foo_bar", "feature/foo_bar"),
            ("x-y_z*w", "x-y_z*w"),
            ("[x](https://evil.example)", "\\[x\\]\\(https://evil.example\\)"),
            ("*bold* text", "\\*bold* text"),
            ("# head", "\\# head"),
            ("> quote", "\\> quote"),
            ("- item", "\\- item"),
            ("+ item", "\\+ item"),
            ("1. first", "1\\. first"),
            ("ok\n2. second", "ok\n2\\. second"),
            ("a\\b", "a\\\\b"),
        ]
        for raw, want in cases:
            with self.subTest(raw=raw):
                self.assertEqual(server.md(raw), want)

    def test_branch_fact_renders_as_written(self):
        env = _event_envelope("stop-completed")
        env["instance"]["branch"] = "feature/foo_bar"
        _, facts, _ = _card_texts(server.build_hook_card(env))
        self.assertEqual(facts["Branch"], "feature/foo_bar")

    def test_cards_escape_user_text(self):
        evil = "[click](https://evil.example)"
        env = _event_envelope("stop-completed", trigger={"type": "user", "name": evil})
        env["instance"]["name"] = evil
        texts, facts, _ = _card_texts(server.build_hook_card(env))
        self.assertNotIn("[click](", texts[0])
        self.assertNotIn("[click](", facts["Triggered by"])

        run = json.loads(json.dumps(SAMPLE_POLICY_RUN))
        run["cleanup_policy"]["instances"][1]["error"] = "see **[here](https://evil.example)**"
        texts, _, _ = _card_texts(server.build_hook_card(run))
        self.assertNotIn("[here](", texts[1])

        deploy = json.loads(json.dumps(SAMPLE_ENVELOPE))
        deploy["instance"]["branch"] = evil
        _, facts, _ = _card_texts(server.build_adaptive_card(deploy))
        self.assertNotIn("[click](", facts["Branch"])

        note = server.build_notification_card({"event_type": "x", "title": evil, "message": evil, "user_display_name": evil})
        texts, _, _ = _card_texts(note)
        self.assertTrue(all("[click](" not in t for t in texts))


class TestTeamsEvents(unittest.TestCase):
    def test_deploy_timeout_not_in_default(self):
        self.assertNotIn("deploy-timeout", server.parse_events(""))
        self.assertIn("deploy-timeout", server.KNOWN_TEAMS_EVENTS)

    def test_unknown_events(self):
        self.assertEqual(server.unknown_events({"stop-completed", "deploy-timeout", "stop-complete"}), ["stop-complete"])

    def test_parse_bool(self):
        self.assertTrue(server.parse_bool("true"))
        self.assertTrue(server.parse_bool(" YES "))
        self.assertFalse(server.parse_bool("false"))
        self.assertFalse(server.parse_bool(""))

    def test_parse_events_default(self):
        self.assertEqual(server.parse_events(""), frozenset(server.DEFAULT_TEAMS_EVENTS))

    def test_parse_events_list(self):
        self.assertEqual(server.parse_events(" stop-completed, delete-completed ,"), frozenset({"stop-completed", "delete-completed"}))

    def test_event_not_in_allow_list_has_no_card(self):
        with patch.object(server, "TEAMS_EVENTS", frozenset({"deploy-finalized"})):
            self.assertIsNone(server.build_hook_card(_event_envelope("stop-completed")))
            self.assertIsNotNone(server.build_hook_card(SAMPLE_ENVELOPE))


class TestPostLogging(unittest.TestCase):
    def test_successful_post_logs_info_line(self):
        resp = MagicMock()
        resp.status = 202
        resp.__enter__.return_value = resp
        with patch.object(server, "TEAMS_WEBHOOK_URL", "https://fake.teams/webhook"), \
             patch("urllib.request.urlopen", return_value=resp), \
             patch("builtins.print") as mock_print:
            server.post_to_teams({"type": "message"}, {"event": "stop-completed", "instance": "demo"})
        mock_print.assert_any_call("INFO posted event=stop-completed instance=demo status=202", flush=True)

    def test_worker_passes_meta(self):
        delivered = []
        q = queue.Queue(maxsize=10)
        with patch.object(server, "_work_queue", q):
            server.enqueue_card({"type": "message"}, event="delete-completed", instance="demo")
        q.put(None)
        with patch.object(server, "_work_queue", q), \
             patch.object(server, "post_to_teams", side_effect=lambda c, m=None: delivered.append(m)):
            server._worker()
        self.assertEqual(delivered, [{"event": "delete-completed", "instance": "demo"}])


class TestHTTPHandlerEvents(unittest.TestCase):
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
        cls.httpd.server_close()

    def _post(self, envelope):
        body = json.dumps(envelope).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/hook", body=body, headers={"Content-Length": str(len(body))})
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        return status

    def test_each_event_enqueues_one_card(self):
        envelopes = [
            _event_envelope("stop-completed"),
            _event_envelope("clean-completed", "draft"),
            _event_envelope("delete-completed", "draft"),
            _event_envelope("rollback-completed", "running", metadata={"outcome": "succeeded"}),
            SAMPLE_POLICY_RUN,
        ]
        for env in envelopes:
            with self.subTest(event=env["event"]), \
                 patch.object(server, "SECRET", ""), \
                 patch.object(server, "TEAMS_WEBHOOK_URL", "https://fake.teams/webhook"), \
                 patch.object(server, "enqueue_card") as mock_enqueue:
                self.assertEqual(self._post(env), 200)
                mock_enqueue.assert_called_once()
                self.assertEqual(mock_enqueue.call_args.kwargs["event"], env["event"])

    def test_policy_card_names_policy_in_log_meta(self):
        with patch.object(server, "SECRET", ""), \
             patch.object(server, "TEAMS_WEBHOOK_URL", "https://fake.teams/webhook"), \
             patch.object(server, "enqueue_card") as mock_enqueue:
            self.assertEqual(self._post(SAMPLE_POLICY_RUN), 200)
        self.assertEqual(mock_enqueue.call_args.kwargs["instance"], "nightly-stop")

    def test_delete_with_clean_posts_one_card(self):
        with patch.object(server, "SECRET", ""), \
             patch.object(server, "TEAMS_WEBHOOK_URL", "https://fake.teams/webhook"), \
             patch.object(server, "enqueue_card") as mock_enqueue:
            self._post(_event_envelope("clean-completed", "draft", metadata={"operation": "delete"}))
            self._post(_event_envelope("delete-completed", "draft"))
        mock_enqueue.assert_called_once()
        self.assertEqual(mock_enqueue.call_args.kwargs["event"], "delete-completed")

    def test_event_outside_allow_list_is_logged_not_posted(self):
        with patch.object(server, "SECRET", ""), \
             patch.object(server, "TEAMS_WEBHOOK_URL", "https://fake.teams/webhook"), \
             patch.object(server, "TEAMS_EVENTS", frozenset({"deploy-finalized"})), \
             patch.object(server, "enqueue_card") as mock_enqueue, \
             patch("builtins.print") as mock_print:
            self.assertEqual(self._post(_event_envelope("stop-completed")), 200)
        mock_enqueue.assert_not_called()
        mock_print.assert_any_call("INFO ignored event=stop-completed (not in TEAMS_EVENTS)", flush=True)


if __name__ == "__main__":
    unittest.main()
