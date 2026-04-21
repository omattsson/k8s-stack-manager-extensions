# New Hook / Extension PR

Thank you for contributing a new hook or extension!

## Checklist
- [ ] My hook follows the conventions in [AGENTS.md](../../AGENTS.md)
- [ ] Includes a test file (`main_test.go` or `test_server.py`) with tests for signature verification, health endpoint, and main logic
- [ ] Includes a `README.md` with usage and configuration
- [ ] Includes `hooks-config.json`, `Dockerfile`, and `k8s/deployment.yaml` (with correct namespace, probes, security)
- [ ] No external dependencies except `requests` for Python
- [ ] Secrets/configuration via environment variables
- [ ] I have tested locally (Go: `go test ./...`, Python: `python3 -m unittest discover .`)

## Description
_What does this hook do? What problem does it solve?_

## Testing
_Describe what was tested and how. Paste test output if possible._

## Deployment Notes
_Are there any special deployment or configuration steps?_

## Additional Context
_Anything else reviewers should know?_
