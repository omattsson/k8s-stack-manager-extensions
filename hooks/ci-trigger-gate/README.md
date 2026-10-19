# ci-trigger-gate

A `pre-deploy` webhook for k8s-stack-manager. It makes sure that each chart has a container image for the deployed branch before the deploy starts.

- If the branch exists in the chart's source repo, the gate builds the image with an Azure DevOps pipeline when the image is missing or the branch has newer commits. The deploy waits for the build.
- If the branch does not exist, or is a default branch, the gate makes the branch tag an alias of a fallback tag (default `latest-dev`).

The registry is Azure Container Registry (ACR). The CI system is Azure DevOps (ADO). By default the gate uses workload identity, so it needs no registry or ADO secret.

## Flow

The gate reads the `charts[]` list of the `pre-deploy` event. Charts run in parallel. The deploy is allowed only if all charts pass.

For each chart:

1. **Tag.** Use `image_tag` from the event. This is the same value that Helm renders for `{{.ImageTag}}`. If the event has no `image_tag`, the gate computes it from the branch with the same rules as k8s-stack-manager.
2. **Skip** the chart if it has no `build_pipeline_id`, or if the tag is a release version (`v1.2.3`, `1.2.3-rc.1`; case-insensitive). The gate does not touch the registry or ADO for these charts.
3. **Input check.** The gate denies the deploy before any registry or ADO call when:
   - the branch has characters other than letters, digits, `.`, `_`, `-` and `/`, contains `..`, starts with `-` or `/`, or is longer than 250 characters;
   - the tag or a repo name is not valid for a container registry.
4. **Repos.** The chart's image repos are `IMAGE_REPO_PREFIX` + chart name, plus the extra repos from `CHART_EXTRA_IMAGES`.
5. **Protected tags.** If the tag is `FALLBACK_TAG`, ends with `ALIAS_MARKER_SUFFIX`, or matches `PROTECTED_TAGS` (default: `latest` and release versions), the gate never aliases or builds it. It allows the deploy if the tag exists in each repo, and denies it if not.
6. **Branch check.** The gate parses `source_repo_url` and asks the ADO Git refs API if `refs/heads/<branch>` exists, and reads its commit (the branch head). Only an exact name match counts. Branches in `DEFAULT_BRANCHES` count as default, also when they exist. When `ADO_ORG` is set, the organization in `source_repo_url` must be `ADO_ORG` (case-insensitive), else the deploy is denied. The project can differ.
7. **Branch does not exist, or is a default branch:** for each repo:
   - `<repo>:<tag>` does not exist: the gate creates an alias (see [Alias markers](#alias-markers)).
   - `<repo>:<tag>` is an alias that the gate made: the gate moves it to the current fallback image if the fallback moved. Otherwise nothing changes.
   - `<repo>:<tag>` is a real image: the gate keeps it (`keeping existing <repo>:<tag>`). It never overwrites a real image. This also keeps the default-branch images that CI publishes (for example `:main`).
8. **Branch exists:** for each repo, a real image under `<repo>:<tag>` is ready, also when it has the same digest as the fallback (CI can build the same commit for both). If the tag is missing or is an alias that the gate made, the gate:
   - reuses a running build of the same pipeline whose `imageTag` template parameter is the tag, or
   - queues a new build with template parameters `branch` and `imageTag`, on the pipeline repo ref `PIPELINE_SOURCE_BRANCH`.

   **New commits** (`REBUILD_ON_NEW_COMMIT`, default `true`). For a real image, the gate reads the label `org.opencontainers.image.revision` (for an image index, of the linux/amd64 image) and compares it with the branch head:
   - The label is the branch head (or a short form of it, at least 7 characters): the gate keeps the image.
   - The label is another commit: the gate logs `Image <repo>:<tag> is at <commit>, branch is at <commit>; building again` and builds, as for a missing tag. When one repo of the chart is older than the branch head, the gate builds the chart.
   - The image has no label, or the gate cannot read it: the gate keeps the image and logs a warning. The gate never denies a deploy for this reason.
   - The gate cannot read the branch head (the source repo is not in Azure DevOps): the gate keeps the image.

   After a build:
   - A reused build can be of an older commit. When its image has a label that is not the branch head, the gate builds once more and waits. It reuses a build that started after the old build (for example from another deploy), or queues a new one.
   - When the label of a new image is not the branch head, the gate logs a warning and allows the deploy. The branch moved during the build, or the pipeline sets the label to another commit (see [Pipeline contract](#pipeline-contract)).
   - The gate remembers each image that it built for a branch head, until the gate restarts. It does not build that image again for the same head, also when the label is wrong. A wrong label costs one build for each new commit, not one build for each deploy.

   The gate polls the build and streams progress. It denies the deploy when the build fails, is canceled, does not start within `QUEUE_TIMEOUT_MINUTES` (when set), does not finish within `BUILD_TIMEOUT_MINUTES`, or when 5 status reads in a row fail. The message includes the build URL. While the build waits for a free agent, the progress lines say so (one line per minute). The gate never cancels a build: a build that is still queued runs later, and the next deploy reuses the build or its image. Note: in a multi-stage pipeline, the build is `inProgress` while a later job waits for an agent. That wait counts against `BUILD_TIMEOUT_MINUTES`. After a successful build, every repo of the chart must have the tag, and the tag must not be an alias that the gate made. Otherwise the gate denies the deploy, because the pipeline did not push `imageTag`.

When one chart fails, the gate stops the other charts and denies the deploy. When the caller goes away, the gate stops polling.

Progress lines start with `LOG: ` and show in the deploy log. The last line is the JSON response `{"allowed": bool, "message": string}`.

Notes:

- If `source_repo_url` is not an Azure DevOps Git URL, the gate cannot check the branch. It assumes that the branch exists. The branch check in step 3 still applies.
- If the fallback tag does not exist in a repo, and the branch tag does not exist either, the deploy is denied.
- Images found for a branch build are cached for `CACHE_TTL_MINUTES`, together with the branch head that the gate checked. A new commit on the branch bypasses the cache. Aliases are never cached.
- Two deploys of the same branch at the same time share one build.

### Alias markers

The gate marks each alias that it makes with a second tag, the marker: `<tag>` + `ALIAS_MARKER_SUFFIX` (default `.alias`). Example: `dev/api:feature-x` and `dev/api:feature-x.alias`.

- To create or move an alias, the gate writes the fallback manifest (same bytes, same Content-Type) to the marker first and then to `<tag>`. A failure between the two writes never leaves an unmarked alias.
- `<repo>:<tag>` is an alias that the gate made only when the marker exists and has the same digest as `<tag>`. In all other cases the tag is a real image.
- After a branch build replaces an alias, the old marker stays. Its digest no longer matches the tag, so it has no effect. The gate does not delete markers. The registry v2 API deletes a manifest by digest, which would also delete the image. A tag-only delete needs a registry-specific API.
- A tag can have at most 128 characters. If `<tag>` + suffix is longer, the gate cuts the tag part and adds `-` and the first 8 hex characters of the SHA-256 of the full tag before the suffix. The result is always the same for the same tag.
- Retention policies must treat `*<suffix>` tags like the other dev tags. If a policy deletes only the marker, the alias becomes a real image for the gate, and it is no longer moved or replaced by a build.
- Aliases made by a gate version without markers have no marker. The gate treats them as real images. Delete those tags once.

Supported `source_repo_url` forms:

```
https://dev.azure.com/{org}/{project}/_git/{repo}
https://{user}@dev.azure.com/{org}/{project}/_git/{repo}
https://{org}.visualstudio.com/{project}/_git/{repo}
https://{org}.visualstudio.com/DefaultCollection/{project}/_git/{repo}
git@ssh.dev.azure.com:v3/{org}/{project}/{repo}
```

## Pipeline contract

Each chart's `build_pipeline_id` is the ID of an ADO pipeline in `ADO_ORG`/`ADO_PROJECT`. The pipeline must:

- accept the template parameters `branch` (the app branch to build) and `imageTag` (the tag to push);
- push `<registry>/<repo>:<imageTag>` for every repo of the chart;
- set the label `org.opencontainers.image.revision` to the commit of the app branch that it builds. Without the label, the gate cannot see new commits and keeps the image (see step 8). Always set the label: an image gets the labels of its base image, and many base images set this label to their own commit.

`Build.SourceVersion` is the commit of the repo that holds the pipeline YAML. When the pipeline checks out the app repo as a second repo, read the app commit after the checkout and pass it to the build, for example:

```yaml
- checkout: self
- checkout: app   # the repository resource of the app
  path: app       # $(Pipeline.Workspace)/app
- script: |
    APP_COMMIT=$(git -C "$(Pipeline.Workspace)/app" rev-parse HEAD)
    docker buildx build --label "org.opencontainers.image.revision=$APP_COMMIT" ...
```

Warning: treat `branch` and `imageTag` as untrusted input. The gate checks them, but the pipeline must not trust them. Do not put `${{ parameters.branch }}` or `${{ parameters.imageTag }}` into a script body. Pass them to scripts as environment variables, for example:

```yaml
- script: ./build.sh "$APP_BRANCH" "$IMAGE_TAG"
  env:
    APP_BRANCH: ${{ parameters.branch }}
    IMAGE_TAG: ${{ parameters.imageTag }}
```

The gate queues the run on `PIPELINE_SOURCE_BRANCH` (default `refs/heads/main`). This is the ref of the repo that holds the pipeline YAML, not the app branch.

## Authentication

### Workload identity (default)

The gate uses `azidentity.NewWorkloadIdentityCredential`. It reads `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE`.

- **ACR:** Entra ID token for `https://containerregistry.azure.net/.default` → `POST /oauth2/exchange` → ACR refresh token → `POST /oauth2/token` with scope `repository:<repo>:pull,push` → access token for the `/v2` calls.
- **ADO:** Entra ID token for `499b84ac-1321-427f-aa17-267ca6975798/.default`, sent as `Authorization: Bearer`.

The gate caches tokens until shortly before they expire. It never logs tokens.

The Azure workload identity webhook is not needed. The pod mounts a projected ServiceAccount token with audience `api://AzureADTokenExchange` and sets the `AZURE_*` variables itself (see `k8s/deployment.yaml`). On the identity, add a federated credential:

- Issuer: the service account issuer of the cluster. Entra ID must be able to read its OIDC discovery document and keys over the internet.
- Subject: `system:serviceaccount:extensions:ci-trigger-gate`
- Audience: `api://AzureADTokenExchange`

### Static credentials (fallback)

- Registry: `REGISTRY_AUTH=basic` with `REGISTRY_USERNAME` and `REGISTRY_PASSWORD` (for example an ACR token).
- ADO: `ADO_AUTH=pat` with `ADO_PAT`.

When `REGISTRY_AUTH` or `ADO_AUTH` is not set, the gate uses workload identity if `AZURE_CLIENT_ID` is set. Otherwise it uses the static mode if its values are set.

## Required permissions

- **Registry:**
  - `AcrPush` on the registry. This role covers all repositories in the registry.
  - For a registry in ABAC mode ("RBAC Registry + ABAC Repository Permissions"), `AcrPush` does not apply. Assign `Container Registry Repository Writer` instead, with a condition that limits it to the repositories under `IMAGE_REPO_PREFIX` (for example, repository name starts with `dev/`).
- **Azure DevOps:** add the identity as a user with **Basic** access. Give it:
  - **View builds** and **Queue builds** on the build pipelines;
  - **Read** on the Git repos that the charts use as source.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8080` | Server listen address |
| `CI_TRIGGER_WEBHOOK_SECRET` | | HMAC-SHA256 secret. Required: the gate does not start without it, unless `ALLOW_UNSIGNED=true`. |
| `ALLOW_UNSIGNED` | `false` | `true` accepts unsigned requests when no secret is set. Use only for local tests. |
| `REGISTRY_URL` | | Registry host, for example `myregistry.azurecr.io` |
| `REGISTRY_AUTH` | see above | `workload-identity` or `basic` |
| `REGISTRY_USERNAME` | | Username for `basic` |
| `REGISTRY_PASSWORD` | | Password for `basic` |
| `ADO_ORG` | | ADO organization of the build pipelines |
| `ADO_PROJECT` | | ADO project of the build pipelines |
| `ADO_AUTH` | see above | `workload-identity` or `pat` |
| `ADO_PAT` | | Personal access token for `pat` |
| `AZURE_CLIENT_ID` | | Client ID of the workload identity |
| `AZURE_TENANT_ID` | | Tenant ID of the workload identity |
| `AZURE_FEDERATED_TOKEN_FILE` | | Path of the projected ServiceAccount token |
| `IMAGE_REPO_PREFIX` | empty | Prefix for repo names, added as is. For example `dev/` gives `dev/<chart>`. |
| `CHART_EXTRA_IMAGES` | empty | More repos per chart: `chart=repoSuffix,chart=repoSuffix`. The repo is `IMAGE_REPO_PREFIX` + suffix. |
| `FALLBACK_TAG` | `latest-dev` | Tag that missing and default branches alias. Always protected. |
| `PROTECTED_TAGS` | `^(latest\|v?\d+\.\d+\.\d+([.-].*)?)$` | Regular expression of tags that the gate never aliases or builds |
| `DEFAULT_BRANCHES` | `main,master` | Branches that always use the fallback alias |
| `ALIAS_MARKER_SUFFIX` | `.alias` | Suffix of the alias marker tag. Starts with `.`, `-` or `_`; at most 32 characters of `[a-zA-Z0-9._-]`. Tags with this suffix are protected. |
| `PIPELINE_SOURCE_BRANCH` | `refs/heads/main` | Ref of the pipeline repo for queued builds |
| `POLL_INTERVAL_SECONDS` | `15` | Seconds between build status polls |
| `BUILD_TIMEOUT_MINUTES` | `25` | Maximum run time of one build. With `QUEUE_TIMEOUT_MINUTES` `0`, the time in the queue counts too. |
| `QUEUE_TIMEOUT_MINUTES` | `0` | Maximum time that one build waits in the queue for a free agent. Then `BUILD_TIMEOUT_MINUTES` counts from the build start. `0`: no separate limit. |
| `CACHE_TTL_MINUTES` | `5` | Minutes to cache found branch images |
| `REBUILD_ON_NEW_COMMIT` | `true` | `true` builds a branch image again when its label `org.opencontainers.image.revision` is not the branch head. `false` keeps every real image. With another value, the gate does not start. |
| `SHUTDOWN_TIMEOUT_SECONDS` | `30` | On SIGTERM, time that in-flight hooks get to finish |

Note: `IMAGE_REPO_PREFIX` is now added as is. Earlier versions added a `/`. Change `dev` to `dev/`.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /hook` | The `pre-deploy` webhook. Checks `X-StackManager-Signature: sha256=<hex>`. |
| `GET /healthz` | Liveness. Makes no external calls. |
| `GET /readyz` | Gets an ACR token and an ADO token. Returns 503 with a short reason if one fails. Use it to check the setup by hand. The example manifest does not use it as the readiness probe, because a short Entra ID, registry or ADO outage would then block all deploys. |

## Shutdown

On SIGTERM or SIGINT, the gate stops accepting requests. In-flight hooks get `SHUTDOWN_TIMEOUT_SECONDS` to finish. After that, the gate stops them and they deny their deploys. The build in ADO continues, and the next deploy reuses it. Set `terminationGracePeriodSeconds` higher than `SHUTDOWN_TIMEOUT_SECONDS` (the example uses 60). A rollout of the gate during a long build wait denies that deploy.

## Deployment

```bash
# Build
docker build -t ci-trigger-gate .

# Deploy to k8s (edit the REPLACE_ME values first)
kubectl apply -f k8s/deployment.yaml
```

The CI workflow publishes the image to `ghcr.io/omattsson/k8s-stack-manager-extensions/ci-trigger-gate`.

## hooks-config.json

Merge this into k8s-stack-manager's hooks configuration:

```json
{
    "subscriptions": [{
        "name": "ci-trigger-gate",
        "events": ["pre-deploy"],
        "url": "http://ci-trigger-gate.extensions.svc.cluster.local:8080/hook",
        "timeout_seconds": 1800,
        "failure_policy": "fail",
        "secret_env": "CI_TRIGGER_WEBHOOK_SECRET"
    }]
}
```

`timeout_seconds` must be longer than the wait of the gate. One build waits at most `BUILD_TIMEOUT_MINUTES`, plus `QUEUE_TIMEOUT_MINUTES` when it is set. Keep at least 2 minutes of margin for status reads and image checks. When `timeout_seconds` ends first, the deploy fails with a hook timeout instead of the gate message. `timeout_seconds: 1800` (30 minutes) fits one build with the defaults. k8s-stack-manager v0.12.0 (the next release) and later allow up to 3600 (60 minutes), for example with `QUEUE_TIMEOUT_MINUTES: "30"` and `BUILD_TIMEOUT_MINUTES: "25"`. Older versions refuse a value above 1800, and the backend does not start. A chart that builds twice (see `REBUILD_ON_NEW_COMMIT`) can wait twice as long. No allowed `timeout_seconds` covers two full waits, so that rare case ends with a hook timeout. The next deploy then finds the image. `failure_policy: fail` blocks the deploy when a build fails or the gate is not reachable. Older k8s-stack-manager versions limit `timeout_seconds` to 600 and do not send `image_tag`. With them, set `timeout_seconds` to 600 and `BUILD_TIMEOUT_MINUTES` to less than 10. The gate then computes the tag itself.
