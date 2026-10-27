# k8s-stack-manager-extensions

Community extensions for [k8s-stack-manager](https://github.com/omattsson/k8s-stack-manager) — ready-to-deploy webhook hooks and actions.

These extensions use the [webhook extension system](https://github.com/omattsson/k8s-stack-manager/blob/main/EXTENDING.md) to add behaviour without forking the core. Each hook is a standalone service you configure via `HOOKS_CONFIG_FILE`.

## Available Extensions

| Extension | Type | Language | Description |
|---|---|---|---|
| [slack-notifier](hooks/slack-notifier/) | Event hook | Python | Post to Slack on deploy success/failure |
| [teams-notifier](hooks/teams-notifier/) | Event hook | Python | Post to Microsoft Teams on deploy, stop, clean, delete, rollback, deploy timeout and cleanup policy runs |
| [webhook-relay](hooks/webhook-relay/) | Event hook | Python | Forward events to arbitrary HTTP endpoints with retry |
| [maintenance-gate](hooks/maintenance-gate/) | Event hook | Python | Block deploys outside business hours, and deploys and rollbacks while a maintenance switch is on |
| [security-scan-gate](hooks/security-scan-gate/) | Event hook | Go | Block deploys when images have critical CVEs (Trivy) |
| [debug-bundle](hooks/debug-bundle/) | Action | Go | Collect pod logs, events, and diagnostics into a downloadable archive |
| [ci-test-runner](hooks/ci-test-runner/) | Action | Go | Run an Azure DevOps test pipeline against a stack and show the progress and test summary in the job log |
| [stack-access](hooks/stack-access/) | Traefik forwardAuth and actions | Go | HTTP basic auth in front of each stack: one password for each stack, an IP bypass, and actions to show, rotate or turn off the password |

## Quick Start

1. **Pick an extension** from the table above
2. **Deploy it** to your cluster (each has a Dockerfile + example k8s manifests)
3. **Register it** in your `HOOKS_CONFIG_FILE` — each extension README has the config snippet
4. **Restart** the k8s-stack-manager backend

See the [Extending k8s-stack-manager](https://github.com/omattsson/k8s-stack-manager/blob/main/EXTENDING.md) guide for the full protocol reference.

## Per-team extensions (`applies_to`)

Teams often need different extensions: team A's stacks use Postgres and team B's use MySQL, or each team has its own test pipeline. Give each action or subscription in `HOOKS_CONFIG_FILE` an `applies_to`, and each team's stacks show and run only their own:

```json
{
  "actions": [
    {"name": "run-tests-team-a", "label": "Run tests", "url": "http://ci-test-runner-team-a.extensions.svc.cluster.local:8080/action",
     "secret_env": "CI_TEST_RUNNER_SECRET", "applies_to": {"template_categories": ["team-a"]}},
    {"name": "run-tests-team-b", "label": "Run tests", "url": "http://ci-test-runner-team-b.extensions.svc.cluster.local:8080/action",
     "secret_env": "CI_TEST_RUNNER_SECRET", "applies_to": {"template_categories": ["team-b"]}}
  ]
}
```

- Keys: `template_ids`, `template_categories` (trimmed, case-insensitive), `definition_ids`, `cluster_ids`. Fields combine with AND, values with OR. Empty or missing: every stack.
- The template is the one of the stack's definition. A stack without a template matches no template scope.
- An action outside its scope is not listed, and invoking it answers 404. A subscription with `applies_to` gets only the events of those stacks. `applies_to` cannot be used with `cleanup-policy-executed`.
- One extension can also route by itself: the envelope and the action request carry `instance.template_id`, `instance.template_name` and `instance.template_category` (omitted when the stack has no template).
- **Server version:** a k8s-stack-manager version without `applies_to` ignores it, and the extension applies to every stack. Upgrade k8s-stack-manager first.

The full rules are in [Limit to some instances](https://github.com/omattsson/k8s-stack-manager/blob/main/backend/docs/hooks.md#limit-to-some-instances-applies_to) and [Per-team hooks and actions](https://github.com/omattsson/k8s-stack-manager/blob/main/EXTENDING.md#per-team-hooks-and-actions).

## Extension Structure

Each extension follows the same layout:

```
hooks/<name>/
  README.md              # What it does, how to configure, how to deploy
  main.go / server.py    # Source code
  Dockerfile             # Container build
  hooks-config.json      # HOOKS_CONFIG_FILE snippet to register it
  k8s/                   # Kubernetes manifests (Deployment + Service + Secret)
```

## Writing Your Own

Any HTTP server that:
1. Accepts `POST` with a JSON envelope
2. Verifies the `X-StackManager-Signature` HMAC-SHA256 header
3. Returns `{"allowed": true/false}` (for event hooks) or arbitrary JSON (for actions)

…is a valid extension. See [EXTENDING.md](https://github.com/omattsson/k8s-stack-manager/blob/main/EXTENDING.md) for the full protocol, envelope shapes, and production tips.

**Contributions welcome!** Open a PR to add your own hooks to the `hooks/` directory.

## License

MIT — see [LICENSE](LICENSE).
