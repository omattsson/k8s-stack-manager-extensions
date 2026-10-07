# ci-trigger-gate

A `pre-deploy` webhook for k8s-stack-manager. It makes sure that each chart has a container image for the deployed branch before the deploy starts.

- If the branch exists in the chart's source repo, the gate builds the image with an Azure DevOps pipeline when needed. The deploy waits for the build.
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
5. **Protected tags.** If the tag is `FALLBACK_TAG` or matches `PROTECTED_TAGS` (default: `latest` and release versions), the gate never aliases or builds it. It allows the deploy if the tag exists in each repo, and denies it if not.
6. **Branch check.** The gate parses `source_repo_url` and asks the ADO Git refs API if `refs/heads/<branch>` exists. Only an exact name match counts. Branches in `DEFAULT_BRANCHES` count as default, also when they exist. When `ADO_ORG` is set, the organization in `source_repo_url` must be `ADO_ORG` (case-insensitive), else the deploy is denied. The project can differ.
7. **Branch does not exist, or is a default branch:** for each repo:
   - `<repo>:<tag>` does not exist: the gate copies the manifest of `<repo>:<FALLBACK_TAG>` to `<repo>:<tag>` (an alias).
   - `<repo>:<tag>` has the fallback digest: nothing to do.
   - `<repo>:<tag>` has a different digest: the gate keeps it (`keeping existing <repo>:<tag>`). It never overwrites an existing tag, because it cannot tell an old alias from a real image. This also keeps the default-branch images that CI publishes (for example `:main`).
8. **Branch exists:** for each repo, the image is ready when `<repo>:<tag>` exists and its digest is not the fallback digest. If an image is missing or is still an alias, the gate:
   - reuses a running build of the same pipeline whose `imageTag` template parameter is the tag, or
   - queues a new build with template parameters `branch` and `imageTag`, on the pipeline repo ref `PIPELINE_SOURCE_BRANCH`.

   The gate polls the build and streams progress. It denies the deploy when the build fails, is canceled, does not finish within `BUILD_TIMEOUT_MINUTES`, or when 5 status reads in a row fail. The message includes the build URL. After a successful build, every repo of the chart must have the tag with a digest that is not the fallback digest. Otherwise the gate denies the deploy, because the pipeline did not push `imageTag`.

When one chart fails, the gate stops the other charts and denies the deploy. When the caller goes away, the gate stops polling.

Progress lines start with `LOG: ` and show in the deploy log. The last line is the JSON response `{"allowed": bool, "message": string}`.

Notes:

- An alias does not follow the fallback tag. When `FALLBACK_TAG` moves to a new image, existing aliases keep the old image. To refresh an alias, delete the branch tag; the next deploy creates it again.
- After the fallback tag moves, an old alias has a digest that is not the fallback digest. If the branch is created later, the gate sees the old alias as a real image and does not build. Delete the tag or run the pipeline by hand in that case.
- If `source_repo_url` is not an Azure DevOps Git URL, the gate cannot check the branch. It assumes that the branch exists. The branch check in step 3 still applies.
- If the fallback tag does not exist in a repo, and the branch tag does not exist either, the deploy is denied.
- Images found for a branch build are cached for `CACHE_TTL_MINUTES`. Aliases are never cached.
- Two deploys of the same branch at the same time share one build.

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
- push `<registry>/<repo>:<imageTag>` for every repo of the chart.

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
| `PIPELINE_SOURCE_BRANCH` | `refs/heads/main` | Ref of the pipeline repo for queued builds |
| `POLL_INTERVAL_SECONDS` | `15` | Seconds between build status polls |
| `BUILD_TIMEOUT_MINUTES` | `25` | Maximum wait for one build |
| `CACHE_TTL_MINUTES` | `5` | Minutes to cache found branch images |
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

`timeout_seconds: 1800` (30 minutes, the maximum in k8s-stack-manager) gives room for a build of `BUILD_TIMEOUT_MINUTES`. `failure_policy: fail` blocks the deploy when a build fails or the gate is not reachable. Older k8s-stack-manager versions limit `timeout_seconds` to 600 and do not send `image_tag`. With them, set `timeout_seconds` to 600 and `BUILD_TIMEOUT_MINUTES` to less than 10. The gate then computes the tag itself.
