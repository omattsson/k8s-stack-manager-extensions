---
paths:
  - "**/k8s/deployment.yaml"
  - "helm/**/templates/deployment.yaml"
---

# Kubernetes Manifest Rules

The same rules are in `.github/instructions/k8s-deployment.instructions.md` for Copilot. Change both.

- In `hooks/*/k8s/` manifests the namespace is `extensions`. Helm templates set no namespace: they use the release namespace.
- The container runs as non-root with minimal permissions.
- Set resource requests and limits.
- Add liveness and readiness probes for `/healthz`.
- Mount secrets as environment variables for HMAC verification.
