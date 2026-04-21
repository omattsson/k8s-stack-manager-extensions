---
description: "Use when: editing or reviewing Kubernetes deployment manifests for hooks. Enforces conventions for namespace, security, probes, and resource limits."
applyTo: "**/k8s/deployment.yaml"
---

# Kubernetes Deployment Instructions

- Namespace must be `extensions`.
- Container must run as non-root with minimal permissions.
- Set resource requests and limits.
- Add liveness/readiness probes for `/healthz`.
- Mount secrets as environment variables for HMAC verification.
- **All hooks must include a test file:** `main_test.go` (Go) or `test_server.py` (Python).
- See [AGENTS.md](../../AGENTS.md) for details.
