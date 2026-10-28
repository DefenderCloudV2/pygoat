# Runner image SBOMs

A reusable composite action using **Bash, Docker, jq, and Syft**. All runtime
commands live in `action.yml`; no Python scripts, Azure credentials, OIDC
configuration, or copied helper files are needed.

It scans **every image ID currently available in the job's Docker image store**
and uploads SPDX JSON SBOMs plus build/image metadata to GitHub Actions. Run it
once after building, in the **same job**, against the same Docker daemon.
No snapshot or state-directory input is needed.

## Use from another repository

```yaml
name: Build image and generate SBOM
on:
  push:
    branches: [master]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5

      - name: Build
        run: docker build --tag example:ci .

      - name: Upload image SBOMs
        if: ${{ !cancelled() }}
        uses: DefenderCloudV2/pygoat/.github/actions/runner-image-sbom@master
```

The example tracks `master`; pin the action reference to a reviewed full
commit SHA for production. The consuming job's repository, commit, and run
populate the metadata, not this action's repository. There is no need to check
out this action's source separately. Within this repository, use
`./.github/actions/runner-image-sbom` after checkout instead.

The source repository must be accessible to the caller and allowed by its
Actions policy. If private, configure action sharing for the permitted
repositories. No additional artifact-upload permission or Entra setup is needed.

## Inputs and outputs

| Input | Meaning |
| --- | --- |
| `artifact-name` | Optional override; default `runner-image-sboms-JOB-RUN_ID-RUN_ATTEMPT`. Give each matrix job or repeated scan a unique name. |
| `retention-days` | Optional GitHub artifact retention; defaults to `30`, subject to repository limits. |

The action exposes `artifact-directory`. It creates its own temporary working
directory; `scan_id` is an opaque identifier derived from that unique directory.

**Migrating from the two-step version:** remove the snapshot step, the `phase`
and `state-directory` inputs, and the condition referencing `steps.runner-images`.
Use the single final step above instead.

## Artifact contents

- `sha256-<image-id>.spdx.json`: one Syft SPDX 2.3 SBOM per unique local image ID.
- `index.json`: scan ID/time; repository and workflow identity; commit/ref;
  run ID/attempt/URL; job and runner OS/architecture; image IDs, tags, registry
  digests, platform and creation time; selected OCI labels; package counts;
  SBOM SHA-256 checksums and byte sizes; and per-image success/failure.

Only OCI source/revision/version labels are included, not arbitrary labels or
environment variables. Syft's version is also recorded in the SBOM's
`creationInfo`. Local image IDs, registry digests, commits, and SBOM checksums are
different identifiers; the index preserves each separately.

No Azure upload occurs, and no `upload-results.json` is generated. A future
GitHub App can download the artifact with repository **Actions: read** permission:

```text
GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts
GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip
```

Use an installation access token, paginate the artifact list, and follow the
download redirect. Retrieve artifacts before their retention period expires.

## Behavior and requirements

Use a Linux runner with Docker, Bash, jq, and GNU coreutils (`sort`,
`sha256sum`, `timeout`, etc.); GitHub-hosted Ubuntu runners include these tools.
The action installs pinned Syft. It does not run the application container.

Docker IDs are deduplicated, so multiple tags for the same image share an SBOM.
The scan includes pre-existing images, images reused by cached builds, untagged
images, and pulled base/helper images, not only this job's build outputs. Use a
dedicated runner: every visible local image is inventoried and uploaded. Images
removed before scanning and BuildKit-only cache stages cannot be discovered in
Docker's image store. An empty store records an empty image array and a notice,
not an error.

Plain `docker build` normally loads images locally. For single-platform Buildx
builds, use `load: true` when compatible with your export/attestation settings,
or pull a published image by immutable digest before the final scan. A separate
job does not share the original runner's image store.

Each image scan has a ten-minute timeout. Failed scans are recorded, partial
SBOM files are removed, other images are still scanned, and the step fails.
Completed SBOMs and the index are uploaded even after a scan failure. The final
step can run after earlier job failures; cancellation or runner loss may prevent
it. This is a final-step action, not an automatic JavaScript `post` hook.

These are unsigned package inventories, not vulnerability scan results or
security endorsements.

## Testing

```sh
bash .github/actions/runner-image-sbom/test.sh
```

The tests execute the actual inline Bash blocks with mocked Docker/Syft commands,
covering pre-existing and untagged images, deduplication, metadata, checksums,
empty images, and errors.
