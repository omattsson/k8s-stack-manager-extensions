---
description: "Use when: editing or reviewing hooks-config.json files for k8s-stack-manager extensions. Reminds agents of the config schema for actions vs subscriptions, and enforces required fields."
applyTo: "**/hooks-config.json"
---

# hooks-config.json Instructions

- **Actions:** Must include `name`, `url`, `description`, `timeout_seconds`, `secret_env`.
- **Subscriptions:** Must include `name`, `events`, `url`, `timeout_seconds`, `failure_policy`, `secret_env`.
- `events` can be `pre-deploy`, `post-deploy`, `deploy-finalized`.
- `failure_policy` should be `fail` or `ignore`.
- All URLs should point to the correct service in the `extensions` namespace.
- **All hooks must include a test file:** `main_test.go` (Go) or `test_server.py` (Python).
- See [AGENTS.md](../../AGENTS.md) for more.
