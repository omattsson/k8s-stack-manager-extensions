# Teams Notifier

Posts deploy results to a Microsoft Teams channel via webhook.

- Subscribes to `post-deploy` events from k8s-stack-manager
- Posts a summary message to the configured Teams webhook URL
- Ignores failures (failure_policy=ignore)

## Usage

1. Set the Teams webhook URL:
   ```sh
   export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."
   export GATE_WEBHOOK_SECRET="your-shared-secret"
   ```
2. Run the server:
   ```sh
   python3 server.py
   ```
3. Register the hook in your hooks-config.json

## Configuration
- `TEAMS_WEBHOOK_URL`: Microsoft Teams incoming webhook URL
- `GATE_WEBHOOK_SECRET`: Shared secret for HMAC signature verification

## Health Check
- `GET /healthz` returns 200 OK
