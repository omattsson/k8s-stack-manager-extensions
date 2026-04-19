# debug-bundle

Collect pod logs, events, resource usage, and `kubectl describe` output for every pod in a stack instance's namespace. Compresses everything into a tarball and returns a download path.

**Language:** Go

**Type:** Action (user-initiated via `POST /api/v1/stack-instances/:id/actions/debug-bundle`)

## How it works

1. Receives an `ActionRequest` from k8s-stack-manager
2. Verifies the HMAC-SHA256 signature
3. Runs `kubectl` commands against the instance's namespace:
   - `kubectl get pods -o wide`
   - `kubectl describe pods`
   - `kubectl logs` for each container
   - `kubectl get events --sort-by=.lastTimestamp`
   - `kubectl top pods` (if metrics-server available)
4. Bundles everything into a `.tar.gz` archive
5. Returns the archive path (or serves it via a download endpoint)

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DEBUG_BUNDLE_SECRET` | Yes | — | HMAC secret shared with k8s-stack-manager |
| `BUNDLE_OUTPUT_DIR` | No | `/tmp/bundles` | Directory to store generated bundles |
| `BUNDLE_TTL_HOURS` | No | `24` | Hours to keep bundles before cleanup |
| `BUNDLE_BASE_URL` | No | — | Public URL prefix for download links (if empty, returns file path) |
| `KUBECONFIG` | No | — | Path to kubeconfig (uses in-cluster config by default) |
| `LOG_TAIL_LINES` | No | `500` | Number of log lines to collect per container |
| `LISTEN_ADDR` | No | `:8080` | Listen address |

### hooks-config.json snippet

```json
{
  "actions": [
    {
      "name": "debug-bundle",
      "url": "http://debug-bundle.extensions.svc.cluster.local:8080/action",
      "description": "Collect pod logs, events, and diagnostics into a downloadable archive",
      "timeout_seconds": 60,
      "secret_env": "DEBUG_BUNDLE_SECRET"
    }
  ]
}
```

## Deploy

```bash
# Build
docker build -t debug-bundle:latest .

# Run locally
export DEBUG_BUNDLE_SECRET=$(openssl rand -hex 32)
go run .

# Deploy to Kubernetes
kubectl apply -f k8s/
```

## Usage

```bash
curl -X POST https://stack-manager.example/api/v1/stack-instances/$ID/actions/debug-bundle \
     -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "action": "debug-bundle",
  "instance_id": "6c9f1e14-...",
  "status_code": 200,
  "result": {
    "bundle_path": "/tmp/bundles/stack-demo-alice-20260419T143022.tar.gz",
    "bundle_url": "http://debug-bundle.extensions.svc.cluster.local:8080/download/stack-demo-alice-20260419T143022.tar.gz",
    "namespace": "stack-demo-alice",
    "pod_count": 5,
    "size_bytes": 245760,
    "collected_at": "2026-04-19T14:30:22Z"
  }
}
```

## Bundle Contents

```
stack-demo-alice-20260419T143022/
  pods.txt                    # kubectl get pods -o wide
  describe-pods.txt           # kubectl describe pods
  events.txt                  # kubectl get events --sort-by=.lastTimestamp
  top-pods.txt                # kubectl top pods (if available)
  logs/
    web-abc123-def45/
      web.log                 # container logs
    api-xyz789-ghi01/
      api.log
      sidecar.log
```

## RBAC

The debug-bundle ServiceAccount needs read access to the target namespaces:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "events"]
    verbs: ["get", "list"]
  - apiGroups: ["metrics.k8s.io"]
    resources: ["pods"]
    verbs: ["get", "list"]
```

A ClusterRole is provided in `k8s/deployment.yaml` — scope it down to specific namespaces if needed.
