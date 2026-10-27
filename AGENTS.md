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
- **Event hooks** (subscriptions): Subscribe to lifecycle events such as `pre-deploy`, `post-deploy`, `deploy-finalized` (the full list is in the k8s-stack-manager [hooks reference](https://github.com/omattsson/k8s-stack-manager/blob/main/backend/docs/hooks.md#available-events)). Return `{ "allowed": true/false }` for gates.
- **Actions**: User-initiated, return arbitrary JSON.
- Both can be limited to some stacks with `applies_to` (templates, template categories, definitions, clusters); see [Per-team extensions](README.md#per-team-extensions-applies_to). The envelope `instance` carries `template_id`, `template_name` and `template_category`: optional fields, omitted when the stack has no template, so read them with a default.

## Languages

- **Go** (`debug-bundle`, `security-scan-gate`): `net/http`, no external deps. Uses external binaries (`kubectl`, `trivy`).
- **Go** (`ci-trigger-gate`, `ci-test-runner`): `net/http` plus the Azure SDK `azidentity` module for workload identity.
- **Go** (`stack-access`): `net/http` plus `k8s.io/client-go` (informers and Lease leader election).
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
- No external library dependencies — Go and Python use only standard libraries. Exceptions: `ci-trigger-gate` and `ci-test-runner` use `azidentity` for workload identity; `stack-access` uses `client-go`.

## Adding a New Hook

1. Create `hooks/<name>/` following the structure above.
2. Implement HMAC signature verification and a `/healthz` endpoint.
3. **Add a test file:** `main_test.go` (Go) or `test_server.py` (Python). All hooks must include unit tests for signature verification, health endpoint, and main logic.
4. Use `hooks-config.json` with either `actions` or `subscriptions` array — see existing hooks for the schema.
5. Provide a `Dockerfile` (non-root) and `k8s/deployment.yaml` with probes and security context.
6. See [EXTENDING.md](https://github.com/omattsson/k8s-stack-manager/blob/main/EXTENDING.md) for the full webhook protocol.
