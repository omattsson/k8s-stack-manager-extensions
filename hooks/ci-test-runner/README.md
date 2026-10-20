# ci-test-runner

A custom action for k8s-stack-manager. A developer selects **Actions > Run tests** on a stack. The runner queues an Azure DevOps (ADO) pipeline that tests that stack. The k8s-stack-manager web UI shows the job log: the build progress, the build result, a test summary and a link to the test results.

The runner is asynchronous. It answers the action call at once with a job ID. A goroutine follows the build, and the web UI polls the job log. By default the runner uses workload identity, so it needs no ADO secret.

## Flow

1. The developer selects **Run tests** and a suite (for example `smoke` or `full`).
2. k8s-stack-manager sends a signed `ActionRequest` to `POST /action`.
3. The runner checks the request (see [Action contract](#action-contract)).
4. When a job of the stack still runs, the runner returns that job. It does not queue a second build.
5. Otherwise the runner queues the pipeline of the suite with the template parameters `stackName`, `namespace`, `branch` and `suite`. It answers with the job ID and the build link.
6. A goroutine reads the build status every `POLL_INTERVAL_SECONDS` and writes the job log.
7. After the build, the runner reads the test runs of the build and writes one summary line.
8. The web UI reads the log at `GET /jobs/{job_id}/log` every 3 seconds until the job ends.

Example job log:

```
2026-01-15T10:15:32Z Queued build 20260115.3 of pipeline 42 (suite smoke): https://dev.azure.com/example-org/example-project/_build/results?buildId=1234
2026-01-15T10:15:47Z Waiting for an agent...
2026-01-15T10:16:47Z Waiting for an agent...
2026-01-15T10:17:02Z Build started
2026-01-15T10:24:17Z Build finished: failed
2026-01-15T10:24:17Z Tests: 120 passed, 3 failed, 5 other
2026-01-15T10:24:17Z Test results: https://dev.azure.com/example-org/example-project/_build/results?buildId=1234&view=ms.vss-test-web.build-test-results-tab
```

## Action contract

### `POST /action`

The request is the `ActionRequest` of k8s-stack-manager (see [EXTENDING.md](https://github.com/omattsson/k8s-stack-manager/blob/main/EXTENDING.md#request-envelope-actionrequest)).

The runner checks the request in this order:

| Check | Answer on failure |
|---|---|
| Body of at most 1 MiB | 413 |
| `X-StackManager-Signature: sha256=<hex>`: the HMAC-SHA256 of the raw body with `CI_TEST_RUNNER_SECRET` (constant-time compare) | 401 |
| Valid JSON | 400 |
| With a secret: `timestamp` and `request_id` are set | 401 |
| `timestamp` (when present) at most 5 minutes from the clock of the runner | 401 |
| `request_id` was not received in the last 10 minutes. This refuses the replay of a captured request. | 409 `{"error": "request_id was already received"}` |
| `instance.id` is set | 400 |
| `parameters.suite` is a suite of `TEST_PIPELINES` | 400, for example `{"error": "Unknown suite \"nightly\". Suites: full, smoke"}` |
| `instance.status` is `running` or `partial` | 409. For `queued`, `deploying` and `stabilizing`: `{"error": "Wait until the stack is running (status: deploying)"}`. For other statuses: `{"error": "Deploy the stack first (status: stopped)"}` |
| `instance.name` and `instance.namespace` are RFC 1123 labels (lowercase letters, digits and `-`, at most 63 characters) | 400 |
| `instance.branch` uses only letters, digits, `.`, `_`, `-` and `/`, has no `..`, does not start with `-` or `/`, and has at most 250 characters. The runner removes a `refs/heads/` prefix. The check refuses all other characters, also `+` and `@`, which Git allows in a branch name. | 400 |
| The runner does not stop (SIGTERM) | 503 |

Then:

- **A job of the stack runs:** 200 with that job. The runner queues nothing.

  ```json
  {"job_id": "job-…", "status": "running", "suite": "smoke", "build_id": 1234, "build_url": "https://…", "message": "A test run for this stack is in progress. This is its log."}
  ```

- **No job runs:** the runner queues the build and answers 202 at once.

  ```json
  {"job_id": "job-0123456789abcdef0123456789abcdef", "status": "started", "suite": "smoke", "build_id": 1234, "build_url": "https://…"}
  ```

- **The queue call fails:** 502 with a short reason, for example `{"error": "Cannot queue the test pipeline: Azure DevOps returned status 403"}`. The answer never contains a token, a URL or the ADO response body. The pod log has the details. The stack can run tests again at once.
- **1000 jobs are in memory and all run:** 503.
- **The 25-second limit ends while the request waits for another request of the same stack:** 503 `{"error": "Another request for this stack is in progress. Try again in a moment."}`.

The 25-second limit counts from the arrival of the request. It covers the wait for another request of the same stack and the queue call.

The job ID is `job-` and 32 hex characters from `crypto/rand`.

The queue call is `POST {org}/{project}/_apis/build/builds?api-version=7.1` with this body:

```json
{
  "definition": {"id": 42},
  "sourceBranch": "refs/heads/main",
  "templateParameters": {
    "stackName": "demo",
    "namespace": "stack-demo-alice",
    "branch": "feature/login",
    "suite": "smoke"
  }
}
```

`sourceBranch` is the `source_branch` of the suite, else `PIPELINE_SOURCE_BRANCH`. It is the ref of the repo that holds the pipeline YAML, not the branch of the stack.

### `GET /jobs/{job_id}/log?instance_id=<id>&offset=<n>&ts=<unix seconds>`

- The signature is the HMAC-SHA256 of the request URI (path and query, exactly as received). A missing or wrong signature gives 401.
- `ts` must be at most 5 minutes from the clock of the runner, else 401.
- `job_id` must match `^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$`. An unknown job, or a job of another `instance_id`, gives 404.
- `offset` is a byte offset (default 0). A value that is not a non-negative integer gives 400.
- The answer is 200 with the log bytes from `offset` to the end (`text/plain`). An offset past the end gives an empty body.
- Headers:
  - `X-Job-Status`: `running`, `succeeded`, `failed` or `canceled`.
  - `X-Log-Offset`: the next offset.

The runner writes the final lines before it sets the final status. A read that gets a final status also gets all lines.

### `GET /healthz` and `GET /readyz`

| Endpoint | Description |
|---|---|
| `GET /healthz` | Liveness. Makes no external calls. |
| `GET /readyz` | Gets an ADO token. Returns 503 with a fixed short reason if this fails. The pod log has the detail. Use it to check the setup by hand. The example manifest does not use it as the readiness probe: a short Entra ID or ADO outage would remove the pod from the Service and stop the job logs. |

## Job

The job polls the build every `POLL_INTERVAL_SECONDS` and writes lines with a UTC time stamp:

- `Queued build <number> of pipeline <id> (suite <suite>): <url>` at the start.
- `Waiting for an agent...` while the build waits for an agent (`notStarted` or `postponed`). At most one line per minute.
- `Build started` once, when the build runs (`inProgress`). A build that goes to `cancelling` before it runs gets no such line.
- `Build finished: <result>` when the build completes.
- `Tests: <passed> passed, <failed> failed, <other> other`, then `Test results: <build url>&view=ms.vss-test-web.build-test-results-tab`. The runner adds up the test runs of the build (`GET {org}/{project}/_apis/test/runs?buildUri=<build uri>&includeRunDetails=true&api-version=7.1`):
  - passed: `passedTests`;
  - failed: `unanalyzedTests` (ADO counts a failed test there until somebody analyzes it);
  - other: the rest of `totalTests` (for example skipped tests), and at least `incompleteTests` plus `notApplicableTests`.
- `No test results published` when the build has no test runs.
- `Cannot read the test results: <reason>` when the test run read fails. This is not a job failure.

Job status:

| Job status | Meaning |
|---|---|
| `running` | The runner follows the build. |
| `succeeded` | The build result is `succeeded`. |
| `failed` | The build result is `failed`, `partiallySucceeded` or another result. Only a build result gives `failed`. |
| `canceled` | The build result is `canceled`. |
| `timed_out` | The runner stopped following the build after `TEST_TIMEOUT_MINUTES` (from the queue time). The build result is not known. Last line: `Stopped following after 60 minutes. The build continues: <url>`. |
| `unknown` | The runner could not read the build status for 10 minutes, or it stopped (SIGTERM) before it could follow the build. The build result is not known. The last line says why, and that the build continues, with the build link. |

The web UI shows each status other than `running` as final. The web UI stops polling after 60 minutes, so keep `TEST_TIMEOUT_MINUTES` at 60 or lower.

A short ADO outage does not end a job. After a failed status read, the runner waits longer before the next read: the interval doubles, up to 2 minutes. On an answer with `Retry-After` (for example 429), the runner waits at least that time (at most 5 minutes). The runner gives up only after failed reads for 10 minutes in a row. One good read resets the count.

The runner never cancels an ADO build.

## Limits

- **Memory only.** The jobs live in the memory of the pod. A restart or a rollout loses them. The web UI then gets 404 for the job log and stops polling. The build in ADO continues. Open the build link to see the result.
- **One replica.** Run one replica. Another replica does not know the jobs and answers 404.
- **Retention.** The runner removes a finished job `JOB_RETENTION_HOURS` after it ended.
- **Job count.** The runner keeps at most 1000 jobs. A request takes a slot before the queue call and gives it back when the queue call fails, so concurrent requests never go over the limit. When the store is full, the runner removes the oldest finished job. When all jobs run, `POST /action` gives 503.
- **Log size.** The log of one job has at most 256 KiB. The runner keeps the start and writes one line `Log truncated at <n> bytes. Later lines are dropped.` The status header still shows the result.
- **One job for each stack.** Two requests for the same stack at the same time queue one build. When the first queue call fails, the second request queues its own build.
- **Replay.** The runner remembers each `request_id` for 10 minutes, in memory. A restart forgets them, but the 5-minute `timestamp` window still applies.
- **Test runs.** The runner reads one page of test runs (up to the ADO page size). A build with more test runs gets a partial summary.

## Pipeline contract

The pipeline of each suite is an ADO YAML pipeline in `ADO_ORG`/`ADO_PROJECT`. It must:

- accept the template parameters `stackName`, `namespace`, `branch` and `suite`;
- test the stack and publish the results in JUnit format with the `PublishTestResults@2` task. Without published results, the log has `No test results published`;
- fail the build when tests fail, so the job status is `failed`.

Warning: treat all parameters as untrusted input. The runner checks them, but the pipeline must not trust them. Do not put `${{ parameters.stackName }}` or another parameter into a script body. Pass them to scripts as environment variables:

```yaml
trigger: none
pr: none

parameters:
  - name: stackName
    type: string
  - name: namespace
    type: string
  - name: branch
    type: string
  - name: suite
    type: string
    default: smoke
    values: [smoke, full]

jobs:
  - job: test
    steps:
      - script: ./run-tests.sh
        displayName: Run tests
        env:
          STACK_NAME: ${{ parameters.stackName }}
          STACK_NAMESPACE: ${{ parameters.namespace }}
          STACK_BRANCH: ${{ parameters.branch }}
          TEST_SUITE: ${{ parameters.suite }}
      - task: PublishTestResults@2
        displayName: Publish test results
        condition: succeededOrFailed()
        inputs:
          testResultsFormat: JUnit
          testResultsFiles: '**/junit*.xml'
```

`run-tests.sh` must exit with a non-zero code when a test fails. `condition: succeededOrFailed()` publishes the results also then.

## Authentication

### Workload identity (default)

The runner uses `azidentity.NewWorkloadIdentityCredential`. It reads `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE`. It gets an Entra ID token for `499b84ac-1321-427f-aa17-267ca6975798/.default` and sends it as `Authorization: Bearer`. It caches the token until shortly before it expires. It never logs tokens.

The Azure workload identity webhook is not needed. The pod mounts a projected ServiceAccount token with audience `api://AzureADTokenExchange` and sets the `AZURE_*` variables itself (see `k8s/deployment.yaml`). On the identity, add a federated credential:

- Issuer: the service account issuer of the cluster. Entra ID must be able to read its OIDC discovery document and keys over the internet.
- Subject: `system:serviceaccount:extensions:ci-test-runner`
- Audience: `api://AzureADTokenExchange`

### Personal access token (fallback)

Set `ADO_AUTH=pat` and `ADO_PAT`. The token needs the scopes **Build (Read & execute)** and **Test Management (Read)**.

When `ADO_AUTH` is not set, the runner uses workload identity if `AZURE_CLIENT_ID` is set. Otherwise it uses `pat` if `ADO_PAT` is set. Without credentials, the runner does not start.

## Required permissions

Add the identity to the ADO organization as a user with **Basic** access. Give it:

- **View builds** and **Queue builds** on the test pipelines;
- **View test runs** in the project.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8080` | Server listen address |
| `CI_TEST_RUNNER_SECRET` | | HMAC-SHA256 secret. Required: the runner does not start without it, unless `ALLOW_UNSIGNED=true`. |
| `ALLOW_UNSIGNED` | `false` | `true` accepts unsigned requests when no secret is set. Use only for local tests. |
| `ADO_ORG` | | ADO organization of the test pipelines. Required. |
| `ADO_PROJECT` | | ADO project of the test pipelines. Required. |
| `ADO_AUTH` | see above | `workload-identity` or `pat` |
| `ADO_PAT` | | Personal access token for `pat` |
| `AZURE_CLIENT_ID` | | Client ID of the workload identity |
| `AZURE_TENANT_ID` | | Tenant ID of the workload identity |
| `AZURE_FEDERATED_TOKEN_FILE` | | Path of the projected ServiceAccount token |
| `TEST_PIPELINES` | | Required. JSON object from suite name to pipeline: `{"smoke": {"pipeline_id": 42}, "full": {"pipeline_id": 42, "source_branch": "refs/heads/main"}}`. A suite name matches `^[a-z0-9][a-z0-9-]{0,31}$`. `pipeline_id` is a positive number. `source_branch` is optional (default `PIPELINE_SOURCE_BRANCH`). At least one suite. Invalid JSON or an unknown field stops the start. |
| `PIPELINE_SOURCE_BRANCH` | `refs/heads/main` | Ref of the pipeline repo for queued builds. Must start with `refs/`. |
| `POLL_INTERVAL_SECONDS` | `15` | Seconds between build status reads |
| `TEST_TIMEOUT_MINUTES` | `60` | Maximum minutes that a job follows its build. The build continues after that. |
| `JOB_RETENTION_HOURS` | `24` | Hours that the runner keeps a finished job |
| `SHUTDOWN_TIMEOUT_SECONDS` | `30` | On SIGTERM, time that in-flight requests get to finish |

A number that is not valid, or is too small, uses the default.

The suite names in `TEST_PIPELINES` and the `options` of the `suite` parameter in `hooks-config.json` must be the same. A suite that is only in `hooks-config.json` gives 400.

## Shutdown

On SIGTERM or SIGINT, the runner stops accepting requests. In-flight requests get `SHUTDOWN_TIMEOUT_SECONDS` to finish. Then the job goroutines stop. The builds in ADO continue. The jobs are lost (see [Limits](#limits)). A request that arrives after the stop started gets 503 before any queue call. When the stop starts during a queue call, the job ends at once with status `unknown`, and the answer still has the build link.

## Deployment

```bash
# Build
docker build -t ci-test-runner .

# Deploy to k8s (edit the REPLACE_ME values first)
kubectl apply -f k8s/deployment.yaml
```

The CI workflow publishes the image to `ghcr.io/omattsson/k8s-stack-manager-extensions/ci-test-runner`.

Local run with a personal access token:

```bash
CI_TEST_RUNNER_SECRET=dev-secret ADO_ORG=example-org ADO_PROJECT=example-project \
ADO_AUTH=pat ADO_PAT=<token> TEST_PIPELINES='{"smoke": {"pipeline_id": 42}}' go run .
```

## hooks-config.json

Merge this into the hooks configuration of k8s-stack-manager:

```json
{
    "actions": [{
        "name": "run-tests",
        "label": "Run tests",
        "description": "Runs the test pipeline in Azure DevOps against this stack.",
        "url": "http://ci-test-runner.extensions.svc.cluster.local:8080/action",
        "secret_env": "CI_TEST_RUNNER_SECRET",
        "timeout_seconds": 30,
        "log_path": "/jobs/{job_id}/log",
        "parameters": [
            {"name": "suite", "label": "Suite", "type": "enum", "options": ["smoke", "full"], "default": "smoke", "required": true}
        ]
    }]
}
```

- `timeout_seconds: 30`: the runner answers within 25 seconds of the request arrival, also when ADO is slow or another request for the same stack is in progress.
- `log_path` makes the action asynchronous. k8s-stack-manager adds `job_id` to the action result, and the web UI polls the job log.
- Set the same secret in `CI_TEST_RUNNER_SECRET` of the runner and of the k8s-stack-manager backend.
- Only the stack owner, a devops user or an admin can run the action and read the job log.
