# k8s-stack-manager-extensions

Community extensions for [k8s-stack-manager](https://github.com/omattsson/k8s-stack-manager) — ready-to-deploy webhook hooks and actions.

These extensions use the [webhook extension system](https://github.com/omattsson/k8s-stack-manager/blob/main/EXTENDING.md) to add behaviour without forking the core. Each hook is a standalone service you configure via `HOOKS_CONFIG_FILE`.

## Available Extensions

| Extension | Type | Language | Description |
|---|---|---|---|
| [slack-notifier](hooks/slack-notifier/) | Event hook | Python | Post to Slack on deploy success/failure |
| [maintenance-gate](hooks/maintenance-gate/) | Event hook | Python | Block deploys outside configurable business hours |
| [security-scan-gate](hooks/security-scan-gate/) | Event hook | Go | Block deploys when images have critical CVEs (Trivy) |
| [debug-bundle](hooks/debug-bundle/) | Action | Go | Collect pod logs, events, and diagnostics into a downloadable archive |

## Quick Start

1. **Pick an extension** from the table above
2. **Deploy it** to your cluster (each has a Dockerfile + example k8s manifests)
3. **Register it** in your `HOOKS_CONFIG_FILE` — each extension README has the config snippet
4. **Restart** the k8s-stack-manager backend

See the [Extending k8s-stack-manager](https://github.com/omattsson/k8s-stack-manager/blob/main/EXTENDING.md) guide for the full protocol reference.

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
