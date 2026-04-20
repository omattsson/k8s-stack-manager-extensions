# teams-notifier

Post deployment results to a Microsoft Teams channel via Incoming Webhook. Fires on `deploy-finalized` events — sends an Adaptive Card with instance details and a link to the stack manager UI.

**Language:** Python 3 (stdlib only — no dependencies)

## How it works

1. Receives the `EventEnvelope` from k8s-stack-manager
2. Verifies the HMAC-SHA256 signature
3. Formats a Microsoft Adaptive Card with instance name, namespace, branch, cluster, and status
4. Posts to the configured Teams webhook URL
5. Returns `{"allowed": true}` (post-* events are fire-and-forget)

Only `deploy-finalized` events trigger a Teams message (covers both success and failure).

## Configuration

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `TEAMS_WEBHOOK_URL` | Yes | Microsoft Teams Incoming Webhook URL |
| `TEAMS_WEBHOOK_SECRET` | Yes | HMAC secret shared with k8s-stack-manager |
| `STACK_MANAGER_URL` | No | Base URL for links in messages (default: `https://stack-manager.example`) |
| `LISTEN_ADDR` | No | Listen address (default: `:8080`) |

### hooks-config.json snippet

```json
{
  "subscriptions": [
    {
      "name": "teams-notifier",
      "events": ["deploy-finalized"],
      "url": "http://teams-notifier.extensions.svc.cluster.local:8080/hook",
      "timeout_seconds": 10,
      "failure_policy": "ignore",
      "secret_env": "TEAMS_WEBHOOK_SECRET"
    }
  ]
}
```

### Setting up the Teams Webhook

1. In your Teams channel, click **...** → **Connectors** (or **Workflows** in newer versions)
2. Add **Incoming Webhook**
3. Name it (e.g., "Stack Manager") and copy the generated URL
4. Set that URL as `TEAMS_WEBHOOK_URL` in the Kubernetes Secret

## Deploy

```bash
# Build
docker build -t teams-notifier:latest .

# Run locally
export TEAMS_WEBHOOK_URL="https://your-tenant.webhook.office.com/webhookb2/..."
export TEAMS_WEBHOOK_SECRET=$(openssl rand -hex 32)
python3 server.py

# Deploy to Kubernetes
kubectl apply -f k8s/
```

## Message Format

**Success:**

> **Deploy succeeded — demo**
>
> | Field | Value |
> |---|---|
> | Namespace | stack-demo-alice |
> | Branch | main |
> | Cluster | dev |
>
> [View instance →]

**Failure:**

> **Deploy failed — demo**
>
> | Field | Value |
> |---|---|
> | Namespace | stack-demo-alice |
> | Branch | main |
> | Cluster | dev |
>
> [View instance →]
