# Agent Instructions

Extensions (hooks and actions) for [k8s-stack-manager](https://github.com/omattsson/k8s-stack-manager). Each extension is a standalone, stateless HTTP server registered via `hooks-config.json` and deployed as a Kubernetes service.

## Architecture

```
hooks/<name>/
  main.go / server.py   # HTTP server
  hooks-config.json      # Registration config (actions or subscriptions)
  Dockerfile
  k8s/deployment.yaml
```

Two types of extensions:
- **Event hooks** (subscriptions): Subscribe to `pre-deploy`, `post-deploy`, `deploy-finalized`. Return `{ "allowed": true/false }` for gates.
- **Actions**: User-initiated, return arbitrary JSON.

## Languages

- **Go** (`debug-bundle`, `security-scan-gate`): `net/http`, no external deps. Uses external binaries (`kubectl`, `trivy`).
- **Python** (`maintenance-gate`, `slack-notifier`): `http.server`, stdlib only — no Flask or other frameworks.

## Build

From any hook directory:
```sh
docker build -t <name>:latest .
```
Go hooks: `go run .` | Python hooks: `python3 server.py`

## Conventions

- All hooks verify `X-StackManager-Signature` HMAC-SHA256 header using a shared secret from env vars.
- All containers run as non-root with minimal permissions.
- Every hook exposes `/healthz` for liveness/readiness probes.
- Kubernetes manifests deploy into the `extensions` namespace.
- No external library dependencies — Go and Python use only standard libraries.

## Adding a New Hook

1. Create `hooks/<name>/` following the structure above.
2. Implement HMAC signature verification and a `/healthz` endpoint.
3. **Add a test file:** `main_test.go` (Go) or `test_server.py` (Python). All hooks must include unit tests for signature verification, health endpoint, and main logic.
4. Use `hooks-config.json` with either `actions` or `subscriptions` array — see existing hooks for the schema.
5. Provide a `Dockerfile` (non-root) and `k8s/deployment.yaml` with probes and security context.
6. See [EXTENDING.md](https://github.com/omattsson/k8s-stack-manager/blob/main/EXTENDING.md) for the full webhook protocol.
