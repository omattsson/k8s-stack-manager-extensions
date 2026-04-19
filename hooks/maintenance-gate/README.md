# maintenance-gate

Block deployments outside configurable business hours. Returns `{"allowed": false}` for `pre-deploy` events that fall outside the permitted schedule. Use this to prevent accidental deploys during nights, weekends, or planned maintenance windows.

**Language:** Python 3 (stdlib only — no dependencies)

## How it works

1. Receives the `EventEnvelope` from k8s-stack-manager
2. Verifies the HMAC-SHA256 signature
3. Checks if the current time falls within allowed deploy hours
4. Returns `{"allowed": false, "message": "..."}` if outside the window
5. Returns `{"allowed": true}` if within the window

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GATE_WEBHOOK_SECRET` | Yes | — | HMAC secret shared with k8s-stack-manager |
| `ALLOWED_DAYS` | No | `mon,tue,wed,thu,fri` | Comma-separated days when deploys are allowed |
| `ALLOWED_START_HOUR` | No | `8` | Earliest hour (0–23) deploys are allowed |
| `ALLOWED_END_HOUR` | No | `17` | Latest hour (0–23) deploys are allowed |
| `TIMEZONE` | No | `Europe/Stockholm` | IANA timezone for schedule evaluation |
| `BYPASS_HEADER` | No | — | If set, requests with this header value in `X-Bypass-Gate` skip the check |
| `LISTEN_ADDR` | No | `:8080` | Listen address |

### hooks-config.json snippet

```json
{
  "subscriptions": [
    {
      "name": "maintenance-gate",
      "events": ["pre-deploy"],
      "url": "http://maintenance-gate.extensions.svc.cluster.local:8080/hook",
      "timeout_seconds": 3,
      "failure_policy": "fail",
      "secret_env": "GATE_WEBHOOK_SECRET"
    }
  ]
}
```

## Deploy

```bash
# Build
docker build -t maintenance-gate:latest .

# Run locally
export GATE_WEBHOOK_SECRET=$(openssl rand -hex 32)
export TIMEZONE="Europe/Stockholm"
python3 server.py

# Deploy to Kubernetes
kubectl apply -f k8s/
```

## Behaviour

| Condition | Response |
|---|---|
| Monday 10:00 | `{"allowed": true}` |
| Saturday 14:00 | `{"allowed": false, "message": "Deploys blocked: outside business hours (sat 14:00 Europe/Stockholm, allowed mon-fri 08:00-17:00)"}` |
| Tuesday 22:00 | `{"allowed": false, "message": "Deploys blocked: outside business hours (tue 22:00 Europe/Stockholm, allowed mon-fri 08:00-17:00)"}` |
| Any time with valid bypass header | `{"allowed": true}` |
