---
paths:
  - "**/hooks-config*.json"
---

# hooks-config.json Rules

The same rules are in `.github/instructions/hooks-config.instructions.md` for Copilot. Change both.

- **Actions:** must include `name`, `url`, `description`, `timeout_seconds`, `secret_env`.
- **Subscriptions:** must include `name`, `events`, `url`, `timeout_seconds`, `failure_policy`, `secret_env`.
- `events` can be `pre-deploy`, `post-deploy`, `deploy-finalized`. The full list is in the k8s-stack-manager [hooks reference](https://github.com/omattsson/k8s-stack-manager/blob/main/backend/docs/hooks.md#available-events).
- `failure_policy` is `fail` or `ignore`.
- All URLs point to the service of the hook in the `extensions` namespace.
