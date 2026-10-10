# teams-notifier

Post stack lifecycle events to a Microsoft Teams channel. The hook sends one Adaptive Card per event, with the stack details, who or what started the operation, and a link to the stack manager UI.

**Language:** Python 3 (stdlib only — no dependencies)

## How it works

1. Receives the `EventEnvelope` from k8s-stack-manager.
2. Verifies the HMAC-SHA256 signature.
3. Builds an Adaptive Card for the event.
4. Posts the card to the Teams webhook (a worker pool sends it; the hook answers at once).
5. Returns `{"allowed": true}` (these events are fire-and-forget).

The hook also accepts notification channel payloads (`event_type`), see the notification channels in the stack manager UI.

## Events

| Event | Card title |
|---|---|
| `deploy-finalized` | "✅ Deploy succeeded — `<name>`" or "❌ Deploy failed — `<name>`" (unchanged) |
| `deploy-timeout` | "⏱ Deploy timed out — `<name>`". Not in the default list: `deploy-finalized` also fires for a timed-out deploy, and its "Deploy failed" card covers it. Add `deploy-timeout` to `TEAMS_EVENTS` for a separate card. |
| `stop-completed` | "⏹ Stack stopped — `<name>`" or "❌ Stop failed — `<name>`" |
| `clean-completed` | "🧹 Stack cleaned — `<name>`" or "❌ Clean failed — `<name>`" |
| `delete-completed` | "🗑 Stack deleted — `<name>`" (no link: the stack does not exist any more) |
| `rollback-completed` | "↩ Rollback succeeded", "❌ Rollback failed", "⛔ Rollback rejected" or "⚠️ Rollback cancelled" — `<name>` (from `metadata.outcome`) |
| `cleanup-policy-executed` | "🧹 Cleanup policy `<policy>`: `<action>` on `<n>` stack(s)" (plus "(dry run)"). The body lists the stacks (at most 20) with their result and error. |

The stop, clean, delete, rollback and timeout cards show the namespace, branch and cluster, and a "Triggered by" fact from the envelope `trigger`:

| `trigger.type` | Shown as |
|---|---|
| `user` | The username (or "a user") |
| `cleanup-policy` | "cleanup policy `<name>`", also in a line such as "Stack stopped by cleanup policy nightly-stop" |
| `ttl` | "TTL expiry" |

The card has no trigger fact when the envelope has no `trigger` (k8s-stack-manager versions before the trigger field).

A cleanup policy run gives one `cleanup-policy-executed` summary card. The successful stop, clean and delete cards of that run (`trigger.type` `cleanup-policy`) are skipped, so a run that stops 30 stacks does not post 31 cards. Set `TEAMS_POLICY_INSTANCE_CARDS=true` to post them too. A failed operation (status `error`) always posts its card, because the summary only says that the operation started.

User text in the cards (stack names, branches, usernames, error texts) is escaped: `[`, `]`, `(`, `)`, `\` and the markdown markers at a line start (`#`, `>`, `-`, `+`, `*`, `1.`). So `[text](url)` shows as plain text and not as a link, and a branch such as `feature/foo_bar` shows as written.

A delete of a deployed stack cleans it first. k8s-stack-manager marks that `clean-completed` with `metadata.operation=delete`; the hook posts no card for it (INFO log line only), so the delete gives one "Stack deleted" card. A failed clean of a delete still posts "Clean failed".

## Configuration

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `TEAMS_WEBHOOK_URL` | Yes | Teams Workflows webhook URL (see below) |
| `TEAMS_WEBHOOK_SECRET` | Yes | HMAC secret shared with k8s-stack-manager |
| `TEAMS_EVENTS` | No | Comma-separated allow list of hook events that post a card (default: all events in the table above except `deploy-timeout`). Other events are logged at INFO and get no card. A name without a card (for example a typing error) gives a WARN line at startup. |
| `TEAMS_POLICY_INSTANCE_CARDS` | No | `true` posts the successful stop, clean and delete cards of a cleanup policy run too (default: `false`, the summary card covers them). |
| `STACK_MANAGER_URL` | No | Base URL for links in messages (default: `https://stack-manager.example`) |
| `SITE_DOMAIN` | No | Domain for the "Open site" link of deploy cards (default: `localhost`) |
| `CARD_TEMPLATE_FILE` | No | Path to a custom card template for `deploy-finalized` (see below) |
| `TEAMS_WORKER_COUNT` | No | Number of worker threads for async delivery (default: `4`) |
| `TEAMS_QUEUE_SIZE` | No | Max queued notifications before dropping (default: `500`) |
| `LISTEN_ADDR` | No | Listen address (default: `:8080`) |

Each successful post writes one log line: `INFO posted event=<event> instance=<name> status=<http status>`. For `cleanup-policy-executed`, `instance` is the policy name.

### hooks-config.json snippet

Subscribe to the events that you want in Teams (see [hooks-config.json](hooks-config.json)):

```json
{
  "subscriptions": [
    {
      "name": "teams-notifier",
      "events": [
        "deploy-finalized",
        "stop-completed",
        "clean-completed",
        "delete-completed",
        "rollback-completed",
        "cleanup-policy-executed"
      ],
      "url": "http://teams-notifier.extensions.svc.cluster.local:8080/hook",
      "timeout_seconds": 10,
      "failure_policy": "ignore",
      "secret_env": "TEAMS_WEBHOOK_SECRET"
    }
  ]
}
```

`cleanup-policy-executed` and the `trigger` field need a k8s-stack-manager version that sends them. Older versions do not fire this event.

### Privacy

The cards go to a Teams channel. They contain stack names, namespaces, branches, cluster IDs, error texts and, from `trigger`, the username of the user who started an operation. Everyone with access to the channel can read them. Post only to a channel with the right audience, or remove events from `TEAMS_EVENTS`.

### Setting up the Teams webhook

Microsoft retired the Microsoft 365 "Incoming Webhook" connectors. Use a Teams Workflows webhook:

1. In the Teams channel, open **...** → **Workflows**.
2. Select the template **Post to a channel when a webhook request is received**.
3. Give the workflow a name (for example "Stack Manager"), select the team and the channel, and save.
4. Copy the webhook URL that the workflow shows.
5. Set that URL as `TEAMS_WEBHOOK_URL` in the Kubernetes Secret.

The workflow accepts the same Adaptive Card message format that this hook sends.

### Card template

`CARD_TEMPLATE_FILE` replaces the built-in card of `deploy-finalized` only. The other events always use the built-in cards. The template is an Adaptive Card message in JSON with `{{variable}}` placeholders:

| Variable | Value |
|---|---|
| `name`, `namespace`, `branch`, `cluster_id`, `status`, `instance_id` | From the envelope `instance` |
| `emoji`, `outcome`, `color` | `✅` / `succeeded` / `good` for a running stack, else `❌` / `failed` / `attention` |
| `instance_url` | `<STACK_MANAGER_URL>/stack-instances/<instance_id>` |
| `site_url`, `site_domain` | `https://<name>.<SITE_DOMAIN>` and `SITE_DOMAIN` |
| `stack_manager_url` | `STACK_MANAGER_URL` |

For notification channel payloads the template gets `event_type`, `title`, `message`, `user_display_name`, `entity_type`, `entity_id`, `stack_manager_url` and `site_domain`.

## Deploy

```bash
# Build
docker build -t teams-notifier:latest .

# Run locally
export TEAMS_WEBHOOK_URL="https://<your workflow webhook URL>"
export TEAMS_WEBHOOK_SECRET=$(openssl rand -hex 32)
python3 server.py

# Test
python3 -m unittest discover .

# Deploy to Kubernetes
kubectl apply -f k8s/
```

The Helm chart in [../../helm/teams-notifier](../../helm/teams-notifier) sets the subscription events and `TEAMS_EVENTS` from the value `events` (an empty list fails the render), and `TEAMS_POLICY_INSTANCE_CARDS` from `policyInstanceCards`.

## Message Format

**Deploy success:**

> **✅ Deploy succeeded — demo**
>
> | Field | Value |
> |---|---|
> | Namespace | stack-demo-alice |
> | Branch | main |
> | Cluster | dev |

**Stop by a cleanup policy** (with `TEAMS_POLICY_INSTANCE_CARDS=true`):

> **⏹ Stack stopped — demo**
>
> Stack stopped by cleanup policy nightly-stop
>
> | Field | Value |
> |---|---|
> | Namespace | stack-demo-alice |
> | Branch | main |
> | Cluster | dev |
> | Triggered by | cleanup policy nightly-stop |

**Cleanup policy run:**

> **🧹 Cleanup policy nightly-stop: stop on 2 stack(s)**
>
> - demo: success
> - old: error — resolving cluster: operation failed
>
> | Field | Value |
> |---|---|
> | Cluster | all |
> | Condition | idle_days:3 |
> | Run | scheduled |
> | Succeeded | 1 |
> | Failed | 1 |
