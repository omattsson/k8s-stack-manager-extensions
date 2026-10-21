# stack-access

HTTP basic auth in front of each stack. Each stack gets its own user name and password, so you can share one stack with an external party without opening the others.

- Traefik sends each request of a protected host to `stack-access` (forwardAuth).
- Requests from the bypass ranges (for example the office and the VPN) pass without a password.
- Other requests need the user name and password of that stack. Without them, the browser shows a login prompt.
- The stack owner (or a devops or admin user) uses three custom actions on the instance page:
  - **Show external access**: the URL, the user name and the password.
  - **Rotate external password**: a new password. The old one stops working within a few seconds (when the cache of each replica has the change).
  - **Turn external password on or off**: off means that everybody who knows the URL can open the stack.

The password lives in a Secret `stack-basic-auth` in the stack namespace. It never goes through the Helm values, the deploy logs or the k8s-stack-manager database: k8s-stack-manager does not store the `result` of a successful action.

## How it works

| Work | Done by |
|---|---|
| `GET /auth` (Traefik forwardAuth) | every replica, from an in-memory cache (informers) |
| Action `show` | every replica, from the cache |
| Actions `rotate` and `set` | the leader; another replica forwards the signed request to the leader |
| Create the Secret of a new stack namespace | the leader |

- **One active writer.** The replicas elect a leader with a Kubernetes Lease (`client-go` leader election). Only the leader writes Secrets.
  - A watchdog ends the term of the leader when the Lease was not renewed within `RENEW_DEADLINE`. That is before `LEASE_DURATION` ends, so the term ends before another replica can take the Lease.
  - A write action stops when the term ends, and it checks the leadership again before each attempt.
  - Each write uses the `resourceVersion` of the Secret. A write that races with another write fails and is tried again; it never overwrites.
- **Lease identity.** `<pod name>@<pod IP>`. The other replicas read the leader address from it.
- **Leader change.** On shutdown the leader releases the Lease, and another replica takes over after about `RETRY_PERIOD` (2 s). When the leader pod dies, the takeover takes up to `LEASE_DURATION` plus `RETRY_PERIOD` (about 17 s). During that time `rotate` and `set` answer 503 "Try again in a minute". The auth check keeps working.
- **Time limits.** The leader finishes a write within 8 s, a follower waits 12 s for the leader, and the k8s-stack-manager action timeout is 15 s. So the user always gets the answer of a write that was done.
- **New stacks.** The leader watches the stack namespaces. A namespace without the Secret gets one: user name = the stack name, a random password, `enabled` = `DEFAULT_ENABLED`. The leader also checks all namespaces every `RESYNC_INTERVAL`, and when a Secret is deleted.
- **Stop and clean.** The Secret is not a Helm object, so a stop (`helm uninstall`) keeps the password. A clean deletes the namespace; the next namespace gets a new password.

### Auth check

1. The client IP is the right-most `X-Forwarded-For` entry. With `trustForwardHeader: false`, Traefik sets it from the TCP peer, so a client cannot choose it. An IP in `BYPASS_CIDRS` passes.
2. `HOST_PATTERN` gets the stack name from `X-Forwarded-Host`. The stack namespace is the namespace whose `INSTANCE_LABEL` has that name.
3. A Secret with `enabled: "false"` passes.
4. A request with the right user name and password passes (constant-time compare).
5. Every other request gets 401 with `WWW-Authenticate: Basic realm="<stack name>"`. This includes an unknown host, a missing namespace or Secret, and two namespaces with the same stack name (fail closed). Set `UNIQUE_INSTANCE_NAMES=true` in k8s-stack-manager when the stack names are in the host names.
6. Before the cache is synced, the answer is 503, and `/readyz` keeps the pod out of the Service.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `STACK_ACCESS_SECRET` | required | HMAC secret of the actions. The same value as the `secret_env` in the k8s-stack-manager hooks config. |
| `ALLOW_UNSIGNED` | `false` | `true` accepts unsigned actions when `STACK_ACCESS_SECRET` is empty (local tests only). |
| `BYPASS_CIDRS` | empty | Comma list of IPs or CIDRs that pass without a password. `/0` is refused. |
| `URL_TEMPLATE` | empty | The URL in the `show` and `rotate` results, for example `https://{instance}.stacks.example.com`. |
| `HOST_PATTERN` | `^(?P<instance>[a-z0-9]([a-z0-9-]*[a-z0-9])?)\.` | Regular expression with the group `instance`: the stack name in the host. The default takes the first DNS label. |
| `NAMESPACE_SELECTOR` | `managed-by=k8s-stack-manager` | Label selector of the stack namespaces. It must not be empty. |
| `INSTANCE_LABEL` | `k8s-stack-manager.io/instance-name` | Namespace label with the stack name (k8s-stack-manager sets it). |
| `SECRET_NAME` | `stack-basic-auth` | Name of the Secret in each stack namespace. Change the RBAC rule and the admission policy with it. |
| `DEFAULT_ENABLED` | `true` | `enabled` of a new Secret. `false`: new stacks are open until the owner turns the password on. |
| `PASSWORD_LENGTH` | `24` | 16 to 128 letters and digits. |
| `LEADER_ELECTION_ENABLED` | `true` | `false` for one replica: the process is always the leader. |
| `POD_NAME`, `POD_NAMESPACE`, `POD_IP` | required with leader election | From the downward API. |
| `LEASE_NAME` | `stack-access` | Lease in `POD_NAMESPACE`. Change the `resourceNames` of the Role `stack-access-leader` with it. |
| `LEASE_DURATION`, `RENEW_DEADLINE`, `RETRY_PERIOD` | `15s`, `10s`, `2s` | Leader election timings. |
| `RESYNC_INTERVAL` | `10m` | Full check of all stack namespaces (minimum `1m`). |
| `SHUTDOWN_DELAY` | `5s` | Time between the readiness failure and the HTTP shutdown. |
| `LISTEN_ADDR` | `:8080` | All replicas must use the same port: the forward to the leader uses it. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. A denied request without credentials logs at `debug` (the normal first step of a browser login). |

## Endpoints

| Endpoint | Purpose |
|---|---|
| `/auth` | Traefik forwardAuth (any method). |
| `POST /actions/show`, `/actions/rotate`, `/actions/set` | k8s-stack-manager actions (HMAC-signed `ActionRequest`). |
| `GET /healthz` | Liveness: the process runs. |
| `GET /readyz` | Readiness: the cache is synced and the process does not stop. |
| `GET /metrics` | Prometheus: `stack_access_auth_requests_total{result}` (`bypass`, `ok`, `disabled`, `denied`, `not_ready`), `stack_access_action_requests_total{action,code}`, `stack_access_secrets_created_total`, `stack_access_leader`. |

### Actions

Each action checks the HMAC signature and the `timestamp` (at most 5 minutes from the clock of the service). It then checks that `instance.namespace` is a stack namespace and that its `INSTANCE_LABEL` equals `instance.name`.

| Action | Result |
|---|---|
| `show` | `{"url", "username", "password", "enabled"}` |
| `rotate` | `{"url", "username", "password", "enabled"}` with the new password. An invalid Secret gets new credentials. |
| `set` (parameter `enabled`, bool) | `{"url", "username", "enabled"}` (no password) |

An error answer is `{"error": "..."}`. k8s-stack-manager stores the message of an error answer, so an error never holds a password.

The leader refuses a second `rotate` or `set` with the same `request_id` (409) while the timestamp of the request is valid. A captured signed request therefore cannot be sent again. A new leader starts with an empty list.

The user name is the stack name when the Secret is made. After a rename of the stack, the user name stays the old name until the next rotate.

## Install

1. Apply [`k8s/admission-policy.yaml`](k8s/admission-policy.yaml) (Kubernetes 1.30 or later). This step is required: RBAC lets the service create any Secret, and the policy limits it to Opaque Secrets named `stack-basic-auth` in stack namespaces.
2. Create the HMAC secret and apply the service (see the comment at the start of [`k8s/deployment.yaml`](k8s/deployment.yaml)). Set `BYPASS_CIDRS` and `URL_TEMPLATE`.
3. Apply [`k8s/networkpolicy.yaml`](k8s/networkpolicy.yaml) with the namespaces of your Traefik, k8s-stack-manager and Prometheus, and [`k8s/traefik-middleware.yaml`](k8s/traefik-middleware.yaml).
4. Add the annotation `traefik.ingress.kubernetes.io/router.middlewares: extensions-stack-access@kubernetescrd` to the stack Ingresses to protect.
5. Add the actions of [`hooks-config.json`](hooks-config.json) to the k8s-stack-manager hooks config, and set `STACK_ACCESS_SECRET` in the backend.

Paths that must stay open (callbacks of other services, APIs with Bearer tokens, public images) need a second Ingress with these paths and no middleware. Traefik routes on the cleaned path, so `..` cannot reach a protected path through an open one.

## Security notes

- The bypass trusts the TCP peer that Traefik sees. Run Traefik with `externalTrafficPolicy: Local` (or another setup that keeps the client IP), and never with trusted forwarded headers for the internet.
- Basic auth has no lockout. A 24-character random password (about 139 bits) makes guessing impractical.
- The logs hold the host, the path (without the query), the client IP and the reason. They never hold the `Authorization` header or a password.
- RBAC lets the service create any Secret; the admission policy limits it to Opaque Secrets named `stack-basic-auth` in stack namespaces. Without the policy the service account could create a service-account-token Secret and read the token. For tighter rights, bind the write rules in each stack namespace (for example with the k8s-stack-manager `backend.namespaceRoleBindings`) and keep only the read rules cluster-wide.
- A follower sends write actions to the address in the Lease. Whoever may change Leases in the service namespace can send those signed requests, and the answers, through another address. Give nobody else that right.
- The NetworkPolicy keeps other pods (for example stack workloads) away from `/auth`, `/actions` and `/metrics`.

## Local development

```sh
export KUBECONFIG=~/.kube/config LEADER_ELECTION_ENABLED=false ALLOW_UNSIGNED=true
go run .
curl -i -H 'X-Forwarded-Host: demo.example.com' -H 'X-Forwarded-For: 198.51.100.7' localhost:8080/auth
```

Tests: `go vet ./... && go test -race ./...`
