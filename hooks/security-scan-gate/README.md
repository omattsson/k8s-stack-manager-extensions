# security-scan-gate

Block deployments when container images have critical or high-severity CVEs. Runs [Trivy](https://github.com/aquasecurity/trivy) against each chart's image before the deploy proceeds.

**Language:** Go

## How it works

1. Receives the `pre-deploy` `EventEnvelope` from k8s-stack-manager
2. Verifies the HMAC-SHA256 signature
3. Extracts image references from the envelope's `values` (looks for `image.repository` + `image.tag` per chart)
4. Runs `trivy image --severity CRITICAL,HIGH --exit-code 1 <image>` for each
5. Returns `{"allowed": false, "message": "..."}` if any image fails the scan
6. Returns `{"allowed": true}` if all images are clean

Results are cached per image digest (in-memory LRU) to keep repeat deploys fast.

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SCANNER_WEBHOOK_SECRET` | Yes | — | HMAC secret shared with k8s-stack-manager |
| `SEVERITY_THRESHOLD` | No | `CRITICAL,HIGH` | Comma-separated Trivy severity levels to fail on |
| `CACHE_TTL_MINUTES` | No | `30` | How long to cache clean scan results |
| `TRIVY_TIMEOUT` | No | `120s` | Per-image scan timeout |
| `LISTEN_ADDR` | No | `:8080` | Listen address |

### hooks-config.json snippet

```json
{
  "subscriptions": [
    {
      "name": "security-scan-gate",
      "events": ["pre-deploy"],
      "url": "http://security-scan-gate.extensions.svc.cluster.local:8080/hook",
      "timeout_seconds": 15,
      "failure_policy": "fail",
      "secret_env": "SCANNER_WEBHOOK_SECRET"
    }
  ]
}
```

## Deploy

```bash
# Build
docker build -t security-scan-gate:latest .

# Run locally
export SCANNER_WEBHOOK_SECRET=$(openssl rand -hex 32)
go run .

# Deploy to Kubernetes
kubectl apply -f k8s/
```

## Image Detection

The scanner looks for image references in the envelope's `values` map with these patterns:
- `<chart>.image.repository` + `<chart>.image.tag` → `repository:tag`
- Falls back to the chart name + version from `charts[]` if no values match

You can also pass images explicitly via the envelope's `metadata` map:
```json
{ "metadata": { "images": "myregistry.io/web:v1.2,myregistry.io/api:v3.0" } }
```
