# Runner and registry image SBOMs

A standalone comparison alternative to [`runner-image-sbom`](../runner-image-sbom/README.md).
The original action is unchanged. This action scans **all local Docker image IDs**
plus **explicit published registry references**, using pinned Syft v1.55.0.
Runtime commands are inline Bash/jq; no Python or copied helper scripts are needed.

Registry sources use `syft scan registry:REGISTRY/REPOSITORY@sha256:DIGEST`.
There is **no `docker pull` or `docker load`** for these references. Syft still
downloads image content to analyze it, but does not add it to Docker's local store.
BuildKit's cache is not inspected: it is not a reliable record of published images.

## Use from another repository

After checkout, registry login, and a Buildx build/push with `id: build`:

```yaml
- name: Scan local and published images
  if: ${{ !cancelled() && steps.build.outcome == 'success' }}
  uses: DefenderCloudV2/pygoat/.github/actions/runner-registry-image-sbom@master
  with:
    registry-images: |
      ghcr.io/example/application@${{ steps.build.outputs.digest }}
    registry-platform: linux/amd64
```

Replace the repository name with the registry/repository used by your build.
Pass one digest reference per line for multiple published outputs. The example
tracks `master`; pin to a reviewed commit SHA after this action is published.
Within this repository, use `./.github/actions/runner-registry-image-sbom`.
The action repository must be accessible and allowed by the caller's Actions policy.

Authenticate to private registries **before** invoking the action, for example
with `docker/login-action` or `az acr login`. Syft uses the runner's Docker
credential configuration, including `DOCKER_CONFIG` and installed credential helpers.
Do not pass credentials or signed URLs in `registry-images`. The action does not
grant registry access or configure Azure federation.

## Inputs and outputs

| Input | Meaning |
| --- | --- |
| `registry-images` | Optional newline-separated `registry/repository@sha256:digest` references. Blank lines and surrounding whitespace are ignored; exact duplicates are scanned once. Tags, URL schemes, and missing digests are rejected. |
| `registry-platform` | Platform for registry scans, default `linux/amd64`; also supports `os/architecture/variant`. |
| `artifact-name` | Optional override; default `runner-registry-image-sboms-JOB-RUN_ID-RUN_ATTEMPT`. |
| `retention-days` | GitHub artifact retention, default `30`, subject to repository limits. |

Output: `artifact-directory`, containing SPDX 2.3 JSON SBOMs and `index.json`.
No Azure Storage upload occurs.

**Multi-platform builds:** a manifest-list digest identifies several platforms.
This action scans only the requested platform, not every platform in the list.
Invoke once per built platform, using unique artifact names for each invocation.
The platform input does not filter local images; every local image ID is scanned.

## Artifact metadata

The index retains schema version 1 and the original build/run identity, per-image
status, package count, SBOM checksum/size, image ID, tags, repository digests,
platform, creation time, and selected OCI source/revision/version labels.
Additional fields make the scanning paths distinguishable:

- `source.type`: `docker` or `registry`.
- `source.reference`: local image ID or exact requested registry digest reference.
- `source.requested_platform`: registry platform, or `null` for local sources.
- `manifest_digest`: the scanned image manifest digest reported by Syft. For a
  multi-platform index, this can differ from the requested top-level digest.
  A Docker export can also produce a different manifest serialization, so this
  field is not a substitute for the original registry reference.

`image_id` is Syft's image ID (the image configuration digest). For local scans,
`source.reference` preserves the ID enumerated by Docker. These can differ with
Docker's containerd image store, which can enumerate manifest/index digests;
the original action records the enumerated Docker ID as its `image_id`.

Image metadata comes from Syft's JSON output from the **same scan** that generates
the SPDX document. The temporary Syft JSON (including raw image configuration)
is not uploaded. Only the selected metadata and SPDX files enter the artifact.
Registry records always retain the requested reference in `repo_digests`.
An empty `tags` array is valid for digest-addressed images.

Local SBOM filenames use the image ID. Registry filenames use a SHA-256 hash of
the requested reference and platform; **that filename hash is not an image digest**.
Local IDs and exact registry references are deduplicated separately. The same
content requested from two registries, or through Docker and a registry, is
intentionally scanned separately so the paths can be compared.

## Side-by-side comparison in this repository

`publish-containers.yml` runs:

1. Build and push the image to ACR and GHCR.
2. Run this action against local images and the published ACR digest **before**
   the workflow pulls the application image.
3. Pull that same ACR digest into Docker and run the unchanged original action.

| Artifact prefix | Discovery | Published application scan |
| --- | --- | --- |
| `runner-registry-image-sboms-` | All local IDs plus the supplied ACR reference | Directly from the registry |
| `runner-image-sboms-` | All local IDs after the pull | From Docker |

Both use the same Syft version and `linux/amd64` application image. Match the
new index's registry record to the old index using the requested registry
reference in `repo_digests`, platform, and revision label. Match local records
using the new `source.reference` and the old `image_id`. Compare package inventories (names, versions, package URLs)
and counts, not SBOM byte hashes: timestamps and source-specific metadata can
make the documents differ. Helper images are expected in both artifacts.

The original pull remains **only for the baseline comparison**. Other consumers
of this new action do not need it. Failed registry scans still fail the job,
but the comparison workflow attempts the original pull and scanner even after
the new action fails. Running both actions doubles much of the scanning work.

## Requirements and failure behavior

Use a Linux runner with Docker, Bash, jq, and GNU coreutils, such as GitHub-hosted
Ubuntu. Docker discovery remains required even when only registry references are
supplied. All local images are scanned, including pre-existing and untagged images;
use a dedicated runner. Registry outputs must be supplied explicitly: this action
does not infer them from workflow files or discover BuildKit cache-only stages.
No application container is started.

Each source scan has a ten-minute timeout. Failed scans are recorded, partial
SBOM files are removed, remaining sources are attempted, and the action fails.
Completed SBOMs and the index are uploaded even after scan failures. Invalid
inputs or Docker discovery failures stop the action before scanning.
With no local images and no registry references, an empty index and notice are
produced. Cancellation or runner loss can prevent artifact upload.

The artifacts are unsigned inventories, not vulnerability assessments. Download
them through the same GitHub Actions artifact APIs described in the original
action's guide; a GitHub App needs repository `Actions: read`.

## Testing

```sh
bash .github/actions/runner-registry-image-sbom/test.sh
```

Tests execute the actual inline scan commands with mocked Docker/Syft, reject
Docker commands other than local discovery, and cover both sources, empty
inputs, alias/reference deduplication, platform forwarding, metadata, checksums,
invalid input/output, and partial failures.
