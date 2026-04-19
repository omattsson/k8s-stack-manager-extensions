# Contributing to k8s-stack-manager-extensions

Thank you for your interest in contributing!

## Adding a New Hook

1. **Create a new directory:**
   - `hooks/<your-hook-name>/`
2. **Implement your hook:**
   - Use Go (`main.go`) or Python (`server.py`).
   - Follow the patterns in existing hooks (stateless HTTP server, HMAC signature verification, `/healthz` endpoint).
3. **Add required files:**
   - `hooks-config.json` (see other hooks for schema)
   - `Dockerfile` (non-root, minimal)
   - `k8s/deployment.yaml` (namespace: `extensions`, probes, security context)
   - **Test file:** `main_test.go` (Go) or `test_server.py` (Python) — tests for signature verification, health endpoint, and main logic are required.
4. **Document your hook:**
   - Add a `README.md` describing usage, configuration, and endpoints.
5. **Test locally:**
   - Go: `go test ./...`
   - Python: `python3 -m unittest discover .`
6. **Update the PR pipeline:**
   - The CI will automatically run all hook tests on pull requests.
7. **Submit a pull request:**
   - Describe your hook and its purpose clearly.

## General Guidelines
- Follow the conventions in [AGENTS.md](AGENTS.md).
- All hooks must be stateless, secure, and expose `/healthz`.
- No external dependencies except for `requests` in Python hooks.
- Use environment variables for secrets and configuration.

For more details, see the documentation in each hook directory and [AGENTS.md](AGENTS.md).
