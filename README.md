# PyGoat
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-9-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

intentionally vuln web Application Security in django.
our roadmap build intentionally vuln web Application in django. The Vulnerability can based on OWASP top ten
<br>

Table of Contents
=================

* [pygoat](#pygoat)
   * [Installation](#installation)
      * [From Sources](#from-sources)
      * [Docker Container](#docker-container)
      * [Installation Video](#installation-video)
   * [Uninstallation](#uninstallation)
   * [Solutions](/Solutions/solution.md)
   * [For Developers](/docs/dev_guide.md)

## Installation

### From Sources

To setup the project on your local machine:
<br>

First, Clone the repository using GitHub website or git in Terminal
```
  git clone https://github.com/adeyosemanputra/pygoat.git
  ### To Download a specific branch
  git clone -b <branch_name> https://github.com/adeyosemanputra/pygoat.git
```
### Windows Notes (PowerShell users)

- PyGoat is tested primarily on Linux/macOS. Windows users are recommended to use:
  - **Docker Desktop** (preferred), or
  - **WSL2 (Ubuntu)** for smoother setup.
- On some Windows environments, the `python3` command may not be available by default.
  - If `python3` is not recognized, try using `python` instead (ensure it points to Python 3.x).
- Ensure Python version is **3.10 or 3.11** for best compatibility.
- Some labs rely on Unix-style commands and may behave differently on native Windows shells.


#### Method 1

1. Install all app and python requirements using installer file - `bash installer.sh`
2. Apply the migrations `python3 manage.py migrate`.<br>
3. Finally, run the development server `python3 manage.py runserver`.<br>
4. The project will be available at <http://127.0.0.1:8000> 

#### Method 2

1. Install python3 requirements `pip install -r requirements.txt`.<br> 
2. Apply the migrations `python3 manage.py migrate`.<br>
3. Finally, run the development server `python3 manage.py runserver`.<br>
4. The project will be available at <http://127.0.0.1:8000> 

#### Method 3

1. Install all app and python requirements using `setup.py` file - `pip3 install .`
2. Apply the migrations `python3 manage.py migrate`.<br>
3. Finally, run the development server `python3 manage.py runserver`.<br>
4. The project will be available at <http://127.0.0.1:8000> 

### Docker Container
1. Install [Docker](https://www.docker.com)
2. Run `docker pull pygoat/pygoat` or `docker pull pygoat/pygoat:latest`
3. Run `docker run --rm -p 8000:8000 pygoat/pygoat:latest`
4. Browse to <http://127.0.0.1:8000> 
5. Remove existing image using `docker image rm pygoat/pygoat` and pull again incase of any error

### Publishing to ACR and GHCR

The `Publish containers to ACR and GHCR` workflow
(`.github/workflows/publish-containers.yml`) runs on pushes to `master` or
manually on `master`. It builds the root Dockerfile once for Linux/amd64 and
pushes the same image to both registries:

- `pygoat22283822.azurecr.io/pygoat`
- `ghcr.io/defendercloudv2/pygoat`

Each image receives a full source-commit SHA tag and a moving `latest` tag.
The workflow verifies both tags in both registries against the build digest
before reporting success. Registry pushes are not atomic: if a run fails after
one push, rerun it to finish publishing to both registries.

Azure uses GitHub OIDC with the `pygoat-github-publisher` managed identity,
with a branch trust for
`repo:DefenderCloudV2@324759237/pygoat@1356696257:ref:refs/heads/master`.
This repository enables immutable OIDC subjects, so the owner and repository
IDs are required in the Azure federated credential, not just their names. It has
`AcrPush` and `Reader` scoped to this registry, not the subscription. `Reader`
allows Azure CLI to resolve the registry's login server and configuration.
The Basic-tier registry
and identity are in `rg-pygoat-containers` in East US. The registry incurs Azure
charges; its admin account is disabled and pulls require authentication.
GHCR publishing uses the workflow's `GITHUB_TOKEN` with `packages: write`;
no Azure client secret or personal access token is stored.

The repository has these Actions variables (identifiers, not secrets):

| Variable | Value |
| --- | --- |
| `CONTAINER_AZURE_CLIENT_ID` | `a9e13f92-93bb-47af-b9e9-e9605052df84` |
| `CONTAINER_AZURE_TENANT_ID` | `7070967c-b4ab-4835-84ac-9b51e0369f43` |
| `CONTAINER_AZURE_SUBSCRIPTION_ID` | `22283822-a9ef-446d-927c-08399daccd79` |
| `CONTAINER_ACR_NAME` | `pygoat22283822` |
| `CONTAINER_ACR_RESOURCE_GROUP` | `rg-pygoat-containers` |

To run manually:

```sh
gh workflow run publish-containers.yml --repo DefenderCloudV2/pygoat --ref master
gh run list --repo DefenderCloudV2/pygoat --workflow publish-containers.yml
gh run watch RUN_ID --repo DefenderCloudV2/pygoat --exit-status
```

For an authenticated ACR pull:

```sh
az acr login --name pygoat22283822 --subscription 22283822-a9ef-446d-927c-08399daccd79
docker pull pygoat22283822.azurecr.io/pygoat:latest
```

GHCR packages are private by default, even for a public source repository.
Authorized users can authenticate to `ghcr.io` and pull the GHCR image;
publishing does not change package visibility. Existing AKS deployment and
archive-attestation behavior is unchanged. This workflow publishes images and
generates SBOM artifacts; it does not deploy PyGoat.

**PyGoat is intentionally vulnerable. Use these images only in an isolated
learning environment, never in production.**

### Reusable post-build SBOM action

All six image-building workflows use `.github/actions/runner-image-sbom`.
It runs on the **same runner and Docker daemon as the build**, not in a separate
workflow or job. Add a single scan as the last step:

```yaml
- uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
- run: docker build --tag example:ci .

- name: Generate SBOMs for all runner images
  if: ${{ !cancelled() }}
  uses: ./.github/actions/runner-image-sbom
```

The action lists all Docker image IDs, including pre-existing and untagged
images, and scans each unique ID once using pinned Syft v1.55.0 with the
explicit `docker:` source. Multiple tags for identical image content share one
SBOM. It inventories the image filesystem without starting a container or
installing anything into the image. The action uses inline Bash, Docker, jq, and
GNU coreutils commands; it has no Python runtime dependency.

Each job uploads `runner-image-sboms-JOB-RUN_ID-RUN_ATTEMPT`, containing SPDX 2.3
JSON files and `index.json` mapping local image IDs, tags, available registry
digests, and scan results to files. Local image IDs are not registry manifest
digests. SBOM generation failures fail the job but scanning continues for other
images and completed results are uploaded. An empty image store produces an explicit
notice and an empty index. The final step also runs after earlier failures,
but cancellation or runner loss can prevent it.

Plain `docker build` outputs are scanned directly. The three push-only Buildx
workflows pull their published image **by immutable digest** into the local
daemon before scanning, preserving their existing build/export and attestation
settings. They do not rely on a moving tag. A push-only or cache-only build is
otherwise invisible to this action; other callers must load such outputs first.

Discovery covers every image in Docker's local store at scan time, including
base/helper images and cached builds reusing a pre-existing ID. Images deleted
before the scan and BuildKit-only cache stages cannot be scanned from that
store. Use a dedicated runner because every visible local image is inventoried.
This is a final-step composite action, not an automatic JavaScript `post` hook;
no snapshot or state-directory input is required.
It generates unsigned package inventories, not vulnerability scan results or
security endorsements. The existing signed registry SBOM experiment remains
separate.

To use this action in another repository, reference
`DefenderCloudV2/pygoat/.github/actions/runner-image-sbom@master` in the final step
(pin to a reviewed commit SHA for production). No helper scripts
need to be copied into the consuming repository. Optional `artifact-name` and
`retention-days` inputs support matrix jobs and custom retention.
See the [reusable action guide](.github/actions/runner-image-sbom/README.md)
for a complete cross-repository example and artifact download APIs.

A separate [local-plus-registry action](.github/actions/runner-registry-image-sbom/README.md)
is available at `.github/actions/runner-registry-image-sbom`. It scans every local
image plus explicit published digest references using Syft's `registry:` source,
without pulling those references into Docker. `publish-containers.yml` runs it
before the existing pull and original scanner, producing separate
`runner-registry-image-sboms-...` and `runner-image-sboms-...` artifacts for comparison.
The registry platform defaults to `linux/amd64`; multi-platform consumers must
invoke it separately for each platform. Private registry login is required.

SBOMs are uploaded **only as GitHub artifacts**. No Azure Storage upload or
Entra/OIDC configuration is required by this action. The index retains build,
image, and checksum metadata so a GitHub App with **Actions: read** permission
can retrieve and correlate the artifacts later.

### Simple ACR-only metadata experiment

`Publish simple image to ACR` (`.github/workflows/publish-acr-simple.yml`) is
manual-only on `master` and reuses the Azure variables above. Like the AKS
workflow, it runs plain `docker build --tag ... .` followed by `docker push`.
It publishes only `pygoat22283822.azurecr.io/pygoat-simple:FULL_COMMIT_SHA`,
keeping the dual-registry image untouched. It adds no explicit image labels,
build arguments, attestations, or provenance flags, and does not use
`docker/build-push-action` or deploy an application.

```sh
gh workflow run publish-acr-simple.yml --repo DefenderCloudV2/pygoat --ref master
```

The metadata inspection step prints image configuration labels, the registry manifest, and
any Git commit and origin URL found in `/app/.git`, without starting PyGoat.
It leaves Docker's default build behavior intact so the logs show what this
simple build actually produces. Distinguish these sources of information:

- A SHA in an image **tag** is explicitly chosen by the workflow, not a label.
- Image **labels** can come from build options, the Dockerfile, or a base image.
- Build **provenance** is separate from labels; its retention depends on the
  builder, image store, and export path.
- Files inside the image can contain repository information even without labels.
  The root Dockerfile uses `COPY . /app/`, and there is no root `.dockerignore`
  excluding `.git`. This experiment preserves that behavior.

The existing AKS workflow creates GitHub deployment records because its job
declares `environment: aks-test`. GitHub Actions creates the deployment and
updates its status automatically; neither `docker push` nor ACR creates it.
The [baseline simple publishing run](https://github.com/DefenderCloudV2/pygoat/actions/runs/39905883783)
had no `environment` and produced no deployment record.

The simple publishing job now declares `environment: acr-push-test` to test
that behavior without AKS. It has separate build and Docker push steps, but
still makes no deployment API calls and deploys no application. GitHub creates
the deployment record for the environment-bound job and updates its status as
the job progresses, independently of the image metadata.

The `acr-push-test` environment allows only the `master` branch. Its Azure
federated credential uses the subject
`repo:DefenderCloudV2@324759237/pygoat@1356696257:environment:acr-push-test`.
An environment-bound job uses this subject instead of the branch subject;
both credentials remain on `pygoat-github-publisher` so the existing
dual-registry workflow continues to work. See
[how environments relate to deployments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments#how-environments-relate-to-deployments).

### Signed SBOM and image provenance in ACR

`Publish image and signed SBOM to ACR` (`.github/workflows/publish-acr-sbom.yml`)
is a separate, manual-only experiment on `master`. It uses the existing Azure
variables and branch-scoped OIDC credential, with no GitHub environment or AKS
deployment. It publishes `pygoat22283822.azurecr.io/pygoat-sbom` with a unique
`COMMIT_SHA-RUN_ID-RUN_ATTEMPT` tag, leaving earlier experiments untouched.

```sh
gh workflow run publish-acr-sbom.yml --repo DefenderCloudV2/pygoat --ref master
gh run list --repo DefenderCloudV2/pygoat --workflow publish-acr-sbom.yml
```

This implements the signed GitHub attestation strategy, not an unsigned ORAS
attachment or BuildKit's embedded SBOM strategy:

1. Build and push a Linux/amd64 image with repository and commit OCI labels.
   BuildKit SBOM/provenance generation is disabled to keep the experiment distinct.
2. Scan the exact published digest with pinned Syft, producing SPDX JSON for
   detected OS and application packages, including installed transitive Python
   dependencies. No SBOM tooling is installed into the application image.
3. Use `actions/attest` twice to sign image build provenance and the image's
   SBOM. Both attestations have the same image name/digest as their subject,
   are uploaded to GitHub, and are pushed to ACR as registry attachments.
   The SBOM JSON is the signed predicate, not a second container image.
4. Fetch both attestations from ACR and verify their signatures, predicate
   types, repository, workflow, source commit, and source ref. Compare the
   verified SBOM predicate with the generated JSON.

The run's downloadable artifact contains `sbom.spdx.json`, both Sigstore
bundles, verification results, and `image.json` with the digest reference.
Artifacts are retained for 30 days. Failed runs may contain only partial
evidence, and image push plus attestation publication is not atomic: check
the whole run's success, not just whether the image exists.

The inventory is scanner-derived, not a guarantee that every component or
direct/indirect relationship can be identified. The workflow checks that both
Debian and Python package entries exist, but it does not claim a complete
source dependency graph. It preserves the root Dockerfile's current build
context, including the `.git` behavior described above.

To independently verify, sign in to ACR, substitute the digest reference from
`image.json` and its commit, and run with a current GitHub CLI:

```sh
az acr login --name pygoat22283822 --subscription 22283822-a9ef-446d-927c-08399daccd79
gh attestation verify oci://pygoat22283822.azurecr.io/pygoat-sbom@sha256:DIGEST --repo DefenderCloudV2/pygoat --bundle-from-oci --predicate-type https://spdx.dev/Document/v2.3 --signer-workflow DefenderCloudV2/pygoat/.github/workflows/publish-acr-sbom.yml --source-digest COMMIT_SHA --source-ref refs/heads/master --deny-self-hosted-runners
gh attestation verify oci://pygoat22283822.azurecr.io/pygoat-sbom@sha256:DIGEST --repo DefenderCloudV2/pygoat --bundle-from-oci --predicate-type https://slsa.dev/provenance/v1 --signer-workflow DefenderCloudV2/pygoat/.github/workflows/publish-acr-sbom.yml --source-digest COMMIT_SHA --source-ref refs/heads/master --deny-self-hosted-runners
```

The provenance step also requests a GitHub artifact **storage record**, using
`artifact-metadata: write`, to associate the digest with its ACR location.
This is distinct from both organization artifact deployment records and the
repository deployment objects created by `environment:`. No artifact deployment
record is submitted by this workflow. Signing an SBOM authenticates the
workflow's statement, not its completeness or the application's security.

### From Docker-Compose 
1. Install [Docker](https://www.docker.com)
2. Run `docker-compose up` or `docker-compose up -d`

## Populate Challenge Data

PyGoat stores challenge definitions in `challenge/challenge.json`.
To populate the `Challenge` table in the database from this file, use the
built-in Django management command:

### Using Docker Compose

```bash
docker compose exec web python manage.py populate_challenges


### Build Docker Image and Run
1. Clone the repository  &ensp; `git clone https://github.com/adeyosemanputra/pygoat.git` 
2. Build the docker image from Dockerfile using &ensp; `docker build -f Dockerfile -t pygoat .`
3. Run the docker image &ensp;`docker run --rm -p 8000:8000 pygoat:latest`
4. Browse to <http://127.0.0.1:8000> or <http://0.0.0.0:8000> 

### Installation video 

1. From Source using `installer.sh`
 - [Installing PyGoat from Source](https://www.youtube.com/watch?v=7bYBJXG3FRQ)
2. Without using `installer.sh`
 - [![](http://img.youtube.com/vi/rfzQiMeiwso/0.jpg)](http://www.youtube.com/watch?v=rfzQiMeiwso "Installation Pygoat")
3. Install with Mac M1 (using Virtualenv)
 - [![](http://img.youtube.com/vi/rfzQiMeiwso/0.jpg)](https://youtu.be/a5UV7mUw580 "Install with Mac M1 - using Virtualenv")


## Uninstallation

### On Debian/Ubuntu Based Systems
- On Debian/Ubuntu based systems, you can use the `uninstaller.sh` script to uninstall `pygoat` along with all it's dependencies.
- To uninstall `pygoat`, simply run:
```bash
$ bash ./uninstaller.sh
```

### On Other Systems
- On other systems, you can use the `uninstaller.py` script to uninstall `pygoat` along with all it's dependencies
- To uninstall `pygoat`, simply run:
```bash
$ python3 uninstaller.py
```

## Solutions 
<a href="/Solutions/solution.md">Solutions to all challenges</a>

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/pwned-17"><img src="https://avatars.githubusercontent.com/u/61360833?v=4?s=100" width="100px;" alt=""/><br /><sub><b>pwned-17</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=pwned-17" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/prince-7"><img src="https://avatars.githubusercontent.com/u/53997924?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Aman Singh</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=prince-7" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/adeyosemanputra"><img src="https://avatars.githubusercontent.com/u/24958168?v=4?s=100" width="100px;" alt=""/><br /><sub><b>adeyosemanputra</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=adeyosemanputra" title="Code">💻</a> <a href="https://github.com/adeyosemanputra/pygoat/commits?author=adeyosemanputra" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/gaurav618618"><img src="https://avatars.githubusercontent.com/u/29380890?v=4?s=100" width="100px;" alt=""/><br /><sub><b>gaurav618618</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=gaurav618618" title="Code">💻</a> <a href="https://github.com/adeyosemanputra/pygoat/commits?author=gaurav618618" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/kUSHAL0601"><img src="https://avatars.githubusercontent.com/u/29600964?v=4?s=100" width="100px;" alt=""/><br /><sub><b>MajAK</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=kUSHAL0601" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/JustinDPerkins"><img src="https://avatars.githubusercontent.com/u/60413733?v=4?s=100" width="100px;" alt=""/><br /><sub><b>JustinPerkins</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=JustinDPerkins" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/Hkakashi"><img src="https://avatars.githubusercontent.com/u/43193113?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Liu Peng</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=Hkakashi" title="Code">💻</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/RupakBiswas-2304"><img src="https://avatars.githubusercontent.com/u/75058161?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Metaphor</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=RupakBiswas-2304" title="Code">💻</a></td>
    <td align="center"><a href="https://whokilleddb.github.io"><img src="https://avatars.githubusercontent.com/u/56482137?v=4?s=100" width="100px;" alt=""/><br /><sub><b>whokilleddb</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=whokilleddb" title="Code">💻</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
