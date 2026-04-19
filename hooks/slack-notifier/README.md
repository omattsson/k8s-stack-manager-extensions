# slack-notifier

Post deployment results to a Slack channel. Fires on `post-deploy` and `deploy-finalized` events — sends a success or failure message with instance details and a link to the stack manager UI.

**Language:** Python 3 (stdlib only — no dependencies)

## How it works

1. Receives the `EventEnvelope` from k8s-stack-manager
2. Verifies the HMAC-SHA256 signature
3. Formats a Slack Block Kit message with instance name, namespace, branch, and status
4. Posts to the configured Slack webhook URL
5. Returns `{"allowed": true}` (post-* events are fire-and-forget)

Only `deploy-finalized` events are posted to Slack (covers both success and failure). `post-deploy` is accepted but can be used for success-only notifications if preferred.

## Configuration

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SLACK_WEBHOOK_URL` | Yes | Slack Incoming Webhook URL |
| `SLACK_WEBHOOK_SECRET` | Yes | HMAC secret shared with k8s-stack-manager |
| `STACK_MANAGER_URL` | No | Base URL for links in messages (default: `https://stack-manager.example`) |
| `LISTEN_ADDR` | No | Listen address (default: `:8080`) |

### hooks-config.json snippet

```json
{
  "subscriptions": [
    {
      "name": "slack-notifier",
      "events": ["deploy-finalized"],
      "url": "http://slack-notifier.extensions.svc.cluster.local:8080/hook",
      "timeout_seconds": 5,
      "failure_policy": "ignore",
      "secret_env": "SLACK_WEBHOOK_SECRET"
    }
  ]
}
```

## Deploy

```bash
# Build
docker build -t slack-notifier:latest .

# Run locally
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxx"
export SLACK_WEBHOOK_SECRET=$(openssl rand -hex 32)
python3 server.py

# Deploy to Kubernetes
kubectl apply -f k8s/
```

## Slack Message Format

**Success:**
> ✅ **Deploy succeeded** — `demo` on `main`
> Namespace: `stack-demo-alice` · Cluster: `dev`
> [View instance →](https://stack-manager.example/stack-instances/123)

**Failure:**
> ❌ **Deploy failed** — `demo` on `main`
> Namespace: `stack-demo-alice` · Cluster: `dev`
> [View instance →](https://stack-manager.example/stack-instances/123)
