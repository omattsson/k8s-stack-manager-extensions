# webhook-relay

Forward k8s-stack-manager events to arbitrary HTTP endpoints. Supports multiple destinations, per-destination event filtering, custom headers, retry with exponential backoff, and a JSON-lines delivery log.

Use this when you need to push events to monitoring systems, CMDBs, incident management, or any custom URL that doesn't have a dedicated extension.

**Language:** Python 3 (stdlib only — no dependencies)

## How it works

1. Receives the `EventEnvelope` from k8s-stack-manager
2. Verifies the HMAC-SHA256 signature
3. Matches the event against each destination's event filter
4. Relays the raw envelope to all matching destinations in parallel
5. Retries failed deliveries up to 3 times with exponential backoff (1s → 2s → 4s)
6. Logs every delivery attempt to a JSON-lines file for debugging
7. Returns `{"allowed": true}` (post-* events are fire-and-forget)

## Configuration

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `RELAY_DESTINATIONS` | Yes | JSON array of destination objects (see below) |
| `RELAY_WEBHOOK_SECRET` | Yes | HMAC secret shared with k8s-stack-manager |
| `RELAY_LOG_FILE` | No | Path for JSON-lines delivery log (disabled if empty) |
| `RELAY_MAX_RETRIES` | No | Max delivery attempts per destination (default: `3`) |
| `RELAY_INITIAL_BACKOFF` | No | Initial retry backoff in seconds (default: `1.0`) |
| `RELAY_REQUEST_TIMEOUT` | No | HTTP request timeout in seconds (default: `5`) |
| `LISTEN_ADDR` | No | Listen address (default: `:8080`) |

### Destination format

```json
[
  {
    "name": "monitoring",
    "url": "https://monitoring.example/webhook",
    "events": ["deploy-finalized"],
    "headers": {"X-Source": "stack-manager"}
  },
  {
    "name": "cmdb",
    "url": "https://cmdb.example/api/hooks",
    "events": ["post-instance-create", "post-instance-delete"],
    "headers": {"Authorization": "Bearer <token>"}
  }
]
```

| Field | Required | Description |
|---|---|---|
| `url` | Yes | Destination HTTP endpoint |
| `name` | No | Label for logs (defaults to `dest-N`) |
| `events` | No | Event filter — empty array means all events |
| `headers` | No | Extra HTTP headers added to the outbound request |

### hooks-config.json snippet

```json
{
  "subscriptions": [
    {
      "name": "webhook-relay",
      "events": ["deploy-finalized", "post-instance-create", "post-instance-delete"],
      "url": "http://webhook-relay.extensions.svc.cluster.local:8080/hook",
      "timeout_seconds": 10,
      "failure_policy": "ignore",
      "secret_env": "RELAY_WEBHOOK_SECRET"
    }
  ]
}
```

Adjust the `events` array to match the union of events your destinations need.

## Deploy

```bash
# Build
docker build -t webhook-relay:latest .

# Run locally
export RELAY_WEBHOOK_SECRET=$(openssl rand -hex 32)
export RELAY_DESTINATIONS='[{"name":"test","url":"https://httpbin.org/post"}]'
python3 server.py

# Deploy to Kubernetes
kubectl apply -f k8s/
```

## Delivery log

When `RELAY_LOG_FILE` is set, every delivery attempt is appended as a JSON line:

```json
{"ts":1713600000.0,"dest":"monitoring","url":"https://monitoring.example/webhook","request_id":"req-abc123","event":"deploy-finalized","attempt":1,"status":200,"ok":true}
{"ts":1713600001.0,"dest":"cmdb","url":"https://cmdb.example/api/hooks","request_id":"req-abc123","event":"deploy-finalized","attempt":3,"status":0,"ok":false,"error":"Connection refused"}
```

Tail the log in-cluster:

```bash
kubectl -n extensions exec deploy/webhook-relay -- tail -f /var/log/webhook-relay/deliveries.jsonl
```

## Retry behaviour

Failed deliveries are retried with exponential backoff:

| Attempt | Delay before |
|---|---|
| 1 | immediate |
| 2 | 1s |
| 3 | 2s |

A delivery "fails" on any non-2xx response or transport error. After exhausting retries the failure is logged and the relay moves on — it never blocks the k8s-stack-manager dispatch.
