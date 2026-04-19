---
description: "Use when: scaffolding a new extension (hook or action) for k8s-stack-manager. Creates the required directory, config, Dockerfile, server stub, and deployment manifest."
---

# New Hook Scaffolding Prompt

This prompt generates all files needed for a new extension:

- `hooks/<name>/main.go` or `server.py` (choose Go or Python)
- `hooks/<name>/hooks-config.json` (actions or subscriptions)
- `hooks/<name>/Dockerfile`
- `hooks/<name>/k8s/deployment.yaml`
- **Test file:** `main_test.go` (Go) or `test_server.py` (Python) — every hook must include unit tests for signature verification, health endpoint, and main logic.

**Conventions:**
- HMAC-SHA256 signature verification
- `/healthz` endpoint
- Non-root container, resource limits, `/healthz` probe
- Registered in `extensions` namespace
- No external dependencies (Go: stdlib, Python: stdlib only)
- **Tests are mandatory for all hooks.**

See [AGENTS.md](../../AGENTS.md) for details.
