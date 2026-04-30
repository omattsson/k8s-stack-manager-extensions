# ci-trigger-gate

A pre-deploy webhook that checks if container images exist for the branch being deployed and triggers Azure DevOps CI builds if they don't — blocking the deploy until all images are ready.

## How it works

1. Receives `pre-deploy` events from k8s-stack-manager
2. For each chart with a `build_pipeline_id`, checks if the branch image exists in the container registry
3. If the image is missing, triggers an ADO build and polls until it completes
4. Streams progress back via `LOG:` lines so the deploy UI shows real-time status
5. Returns `allowed: true` when all images are ready, or `allowed: false` if any build fails

### Skip logic

Charts are skipped (no registry check, no build trigger) when:
- `build_pipeline_id` is empty (public/pre-built chart)
- Branch matches semver pattern (`vN.N.N`) — release images are always pre-built
- Branch is `main` or `master` — CI builds on push

### Image caching

Successfully verified images are cached in-memory for `CACHE_TTL_MINUTES` (default 5m) to avoid redundant registry checks on rapid redeploys.

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CI_TRIGGER_WEBHOOK_SECRET` | no | | HMAC-SHA256 signing secret |
| `LISTEN_ADDR` | no | `:8080` | Server listen address |
| `REGISTRY_URL` | yes | | Container registry host (e.g. `myacr.azurecr.io`) |
| `REGISTRY_USERNAME` | yes | | Registry auth username |
| `REGISTRY_PASSWORD` | yes | | Registry auth password |
| `ADO_ORG` | yes | | Azure DevOps organization |
| `ADO_PROJECT` | yes | | Azure DevOps project |
| `ADO_PAT` | yes | | ADO Personal Access Token (Build read+execute scope) |
| `POLL_INTERVAL_SECONDS` | no | `15` | Seconds between build status polls |
| `CACHE_TTL_MINUTES` | no | `5` | Minutes to cache verified image existence |

## Deployment

```bash
# Build
docker build -t ci-trigger-gate .

# Deploy to k8s
kubectl apply -f k8s/deployment.yaml
```

Add the subscription to k8s-stack-manager's hooks config (see `hooks-config.json`).

## hooks-config.json

Merge this into k8s-stack-manager's hooks configuration:

```json
{
    "subscriptions": [{
        "name": "ci-trigger-gate",
        "events": ["pre-deploy"],
        "url": "http://ci-trigger-gate.extensions.svc.cluster.local:8080/hook",
        "timeout_seconds": 600,
        "failure_policy": "fail",
        "secret_env": "CI_TRIGGER_WEBHOOK_SECRET"
    }]
}
```

The 600s timeout allows for long CI builds. `failure_policy: fail` ensures deploys are blocked when builds fail or the gate is unreachable.
