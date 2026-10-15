# maintenance-gate

Block deployments outside configurable business hours, and deployments and rollbacks while an operator has switched maintenance on. Returns `{"allowed": false}` for `pre-deploy` and `pre-rollback` events. Use the schedule to prevent accidental deploys during nights or weekends. Use the maintenance switch to pause deploys while you change the platform, for example during a `helm upgrade` of the CNI, the ingress controller or k8s-stack-manager itself.

**Language:** Python 3 (stdlib only — no dependencies)

## How it works

1. Receives the `EventEnvelope` from k8s-stack-manager
2. Verifies the HMAC-SHA256 signature
3. Checks the maintenance switch (when `STATE_CONFIGMAP` is set)
4. For `pre-deploy` only: checks if the current time falls within allowed deploy hours (when `SCHEDULE_ENABLED` is true)
5. Returns `{"allowed": false, "message": "..."}` if the switch is on or the time is outside the window
6. Returns `{"allowed": true}` otherwise

A refused deploy fails in k8s-stack-manager with the gate message. Deploy again when the gate is open.

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GATE_WEBHOOK_SECRET` | Yes | — | HMAC secret shared with k8s-stack-manager |
| `ALLOWED_DAYS` | No | `mon,tue,wed,thu,fri` | Comma-separated days when deploys are allowed |
| `ALLOWED_START_HOUR` | No | `8` | Earliest hour (0–23) deploys are allowed |
| `ALLOWED_END_HOUR` | No | `17` | Latest hour (0–23) deploys are allowed |
| `TIMEZONE` | No | `Europe/Stockholm` | IANA timezone for schedule evaluation |
| `BYPASS_HEADER` | No | — | If set, requests with this header value in `X-Bypass-Gate` skip the check (k8s-stack-manager itself sends no such header) |
| `LISTEN_ADDR` | No | `:8080` | Listen address |
| `SCHEDULE_ENABLED` | No | `true` | `false` turns the schedule check off. Only the maintenance switch then closes the gate. The schedule applies to `pre-deploy` only, so an emergency rollback outside business hours works. |
| `STATE_CONFIGMAP` | No | — | Name of the maintenance switch ConfigMap (for example `maintenance-gate-state`). Not set: no switch. |
| `STATE_NAMESPACE` | No | the pod namespace | Namespace of the ConfigMap |
| `STATE_CACHE_SECONDS` | No | `5` | How long the gate caches the switch state |

## Maintenance switch

The gate reads the ConfigMap `STATE_CONFIGMAP` through the Kubernetes API (the service account of the pod) on each request, with a short cache. The key `state.json` holds:

```json
{"enabled": true, "reason": "CNI upgrade", "until": "2026-10-15T15:00:00Z", "by": "alice@host"}
```

| State | Result |
|---|---|
| No ConfigMap, no `state.json`, or `"enabled": false` | Open |
| `"enabled": true` and `until` in the future (or no `until`) | Closed: `Deploys paused: CNI upgrade (until 2026-10-15 17:00 Europe/Stockholm)` |
| `"enabled": true` and `until` in the past | Open: a forgotten switch reopens by itself |
| `state.json` is not valid (also a missing `enabled`), or the API read fails | Closed (fail closed), with a clear message |

The gate needs `get` on that one ConfigMap (`k8s/deployment.yaml` has the ServiceAccount, the Role and the RoleBinding). Operators write the ConfigMap with their own `kubectl` rights through `scripts/maintenance.sh`:

```bash
./scripts/maintenance.sh on --reason "CNI upgrade" --for 30m   # m, h or d; default 1h
./scripts/maintenance.sh status
./scripts/maintenance.sh off
```

Options: `--namespace` (default `extensions`), `--name` (default `maintenance-gate-state`), `--context`. The name must match `STATE_CONFIGMAP` and the Role: for another name the gate gets 403 and stays closed. The operator needs `get`, `create` and `patch` on ConfigMaps in that namespace.

The switch stops new deploys and rollbacks only. Before a change that restarts k8s-stack-manager or the nodes, wait until no stack deploys (status `queued`, `deploying` or `stabilizing`). Stops and cleans (TTL reaper, cleanup policies) have no pre-hook, so the gate cannot pause them.

### hooks-config.json snippet

```json
{
  "subscriptions": [
    {
      "name": "maintenance-gate",
      "events": ["pre-deploy", "pre-rollback"],
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
| Maintenance switch on (`reason` "CNI upgrade") | `{"allowed": false, "message": "Deploys paused: CNI upgrade (until ...)"}` |
