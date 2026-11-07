---
paths:
  - "**/hooks-config*.json"
  - "helm/**/templates/hooks-configmap.yaml"
---

# hooks-config.json Rules

The same rules are in `.github/instructions/hooks-config.instructions.md` for Copilot. Change both.

- **Actions:** must include `name`, `url`, `description`, `timeout_seconds`, `secret_env`.
- **Subscriptions:** must include `name`, `events`, `url`, `timeout_seconds`, `failure_policy`, `secret_env`.
- `events` can be `pre-deploy`, `post-deploy`, `deploy-finalized`. The full list is in the k8s-stack-manager [hooks reference](https://github.com/omattsson/k8s-stack-manager/blob/main/backend/docs/hooks.md#available-events).
- `failure_policy` is `fail` or `ignore`.
- `applies_to` is optional on actions and subscriptions: `template_ids`, `template_categories`, `definition_ids`, `cluster_ids` (lists of strings, at most 50 each). Spell the key `applies_to` exactly (`appliesTo` stops the k8s-stack-manager startup). Do not combine it with the `cleanup-policy-executed` event, and do not use `"all"` in `cluster_ids`. See README.md, "Per-team extensions".
- URLs in `hooks/*/hooks-config*.json` point to the service of the hook in the `extensions` namespace. A Helm chart builds the URL from the release namespace (`<chart>.serviceUrl` in `_helpers.tpl`); never hard-code `extensions` there.
