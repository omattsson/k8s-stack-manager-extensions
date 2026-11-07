---
description: "Use when: editing or reviewing hooks-config.json files for k8s-stack-manager extensions. Reminds agents of the config schema for actions vs subscriptions, and enforces required fields."
applyTo: "**/hooks-config*.json,helm/**/templates/hooks-configmap.yaml"
---

# hooks-config.json Instructions

- **Actions:** Must include `name`, `url`, `description`, `timeout_seconds`, `secret_env`.
- **Subscriptions:** Must include `name`, `events`, `url`, `timeout_seconds`, `failure_policy`, `secret_env`.
- `events` are k8s-stack-manager lifecycle events, for example `pre-deploy`, `post-deploy`, `deploy-finalized` (full list: the k8s-stack-manager `backend/docs/hooks.md`, "Available events").
- `failure_policy` should be `fail` or `ignore`.
- `applies_to` is optional on actions and subscriptions: `template_ids`, `template_categories`, `definition_ids`, `cluster_ids` (lists of strings, at most 50 each). Spell the key `applies_to` exactly (`appliesTo` stops the k8s-stack-manager startup). Do not combine it with the `cleanup-policy-executed` event, and do not use `"all"` in `cluster_ids`. See [README.md](../../README.md#per-team-extensions-applies_to).
- URLs in `hooks/*/hooks-config*.json` point to the service of the hook in the `extensions` namespace. A Helm chart builds the URL from the release namespace (`<chart>.serviceUrl` in `_helpers.tpl`); never hard-code `extensions` there.
- **All hooks must include a test file:** `main_test.go` (Go) or `test_server.py` (Python).
- See [AGENTS.md](../../AGENTS.md) for more.
- The same rules are in `.claude/rules/hooks-config.md` for Claude Code. Change both.
