# Discover pushed images before generating SBOMs

This reusable Linux composite action combines **live Docker push events** with
**Buildx output metadata**. It returns deduplicated
`registry/repository@sha256:digest` references and a discovery report for
[`runner-registry-image-sbom`](../runner-registry-image-sbom/README.md).
It neither builds nor pushes images itself.

Use two explicit invocations in the **same job**: `start` before builds/pushes,
then `collect` after they finish and before registry credentials are removed.
These are not JavaScript `pre`/`post` hooks. Local composite actions cannot
declare those hooks, and GitHub does not support `runs.pre` for local actions.

## Buildx and ordinary Docker example

After checkout, registry login, and Docker/Buildx setup:

```yaml
- name: Start pushed-image discovery
  id: push-monitor
  uses: DefenderCloudV2/pygoat/.github/actions/discover-pushed-images@master
  with:
    phase: start

- name: Build and push
  id: build
  uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8 # v6
  with:
    context: .
    push: true
    tags: |
      ghcr.io/example/application:${{ github.sha }}
      ghcr.io/example/application:latest

# Any ordinary docker push commands also go between start and collect.

- name: Discover published images
  id: discovered
  if: ${{ !cancelled() && steps.push-monitor.outcome == 'success' }}
  uses: DefenderCloudV2/pygoat/.github/actions/discover-pushed-images@master
  with:
    phase: collect
    state-directory: ${{ steps.push-monitor.outputs.state-directory }}
    buildx-metadata: ${{ steps.build.outputs.metadata }}

- name: Generate discovered-image SBOMs
  if: ${{ !cancelled() && steps.discovered.outputs.report-path != '' }}
  uses: DefenderCloudV2/pygoat/.github/actions/runner-registry-image-sbom@master
  with:
    registry-images: ${{ steps.discovered.outputs.registry-images }}
    discovery-report: ${{ steps.discovered.outputs.report-path }}
    scan-local-images: "false"
    registry-platform: linux/amd64
    exclude-images: |
      ghcr.io/github/**
      moby/**
      ghcr.io/dependabot/**
```

Replace the example image names and pin all reusable actions to a reviewed commit
once published. Within this repository, use the corresponding
`./.github/actions/...` paths. The caller needs access to the action repository
and every private image registry.

For ordinary `docker build` followed by `docker push`, omit `buildx-metadata`.
No tags/digests need to be manually enumerated: the Docker events supply names.
For Buildx, **pass the output metadata**: separate BuildKit builders can push
without producing any host Docker push events or local image.

## Inputs and outputs

| Input | Meaning |
| --- | --- |
| `phase` | Required: `start` or `collect`. |
| `state-directory` | Required for `collect`: the directory returned by `start`. Bound to repository, run, attempt, and job. |
| `buildx-metadata` | Optional JSON object from `steps.build.outputs.metadata`, or an array of such objects for multiple successful push builds. |
| `buildx-metadata-files` | Optional newline-separated file paths produced with `docker buildx build --push --metadata-file FILE`. Files must contain an object or array of objects, not a Bake target map. |

Only supply metadata from **successful push-enabled builds in the current job**.
The `image.name` field provides all exported names; `containerimage.digest`
provides the immutable manifest/index digest. Metadata alone does not prove a
push occurred, so each discovered digest is also checked in the registry.
Raw provenance, build arguments, and image labels are not copied into the report.

For a CLI build, for example:

```sh
docker buildx build --push --tag ghcr.io/example/application:ci \
  --metadata-file "$RUNNER_TEMP/application-build.json" .
```

Then pass `${{ runner.temp }}/application-build.json` to
`buildx-metadata-files` in `collect`. Do not reuse stale metadata files.

| Output | Meaning |
| --- | --- |
| `state-directory` | Emitted by `start`; unique state directory under `RUNNER_TEMP`. |
| `registry-images` | Emitted by `collect`; one immutable reference per line, deduplicated by repository and digest. |
| `report-path` | Emitted by `collect`; `discovery.json` with job identity, capture window, images, evidence, warnings, and errors. |

Different tags of one repository/digest share a scan target, with each input tag
retained as evidence. Mirrors remain separate targets. A Docker event and Buildx
metadata can both contribute evidence to the same target.

## Coverage and limitations

- Live capture starts before the build, rather than relying only on Docker's
  bounded retrospective event history (last 256 events). The collector retains
  only push-event identity and timestamps, and is stopped by `collect`. An
  interrupted stream fails discovery; it is not silently restarted.
- **Docker push events do not reliably include a manifest digest.** Tagged event
  references are resolved through the registry **at collection time**, not
  treated as historical immutable identities. The report and log warn about this.
  If a tag is overwritten between a push and collection, the earlier digest
  cannot be recovered reliably this way. Use unique tags or capture immutable
  build/push outputs instead; Buildx metadata retains the build's digest.
- A content-only actor ID without a tagged/digested reference fails discovery
  rather than guessing `latest` or treating a local/config ID as a manifest digest.
- This is a publication inventory, not proof that an image was built in this job.
  An ordinary push can republish an existing image. Unpushed local builds,
  intermediate/cache-only stages, deleted registry images, unrelated builders,
  and Buildx builds whose metadata was not supplied are not covered.
- Use a dedicated daemon. Docker events have no GitHub job identity: another
  process using that daemon during the capture window can contribute events.
  Changing daemons between start and collect is rejected.
- The companion scanner defaults to scanning local images as well. Set
  `scan-local-images: "false"` as above to scan only discovered publications.
  This avoids incidental base/helper images; configured namespace exclusions
  still apply. Discovery itself verifies all references before scanner exclusions.
- Registry SBOMs are generated without pulling into Docker. A multi-platform
  index still needs a separate scanner invocation per requested platform.

Requirements: Linux, Bash, jq, GNU coreutils, a running Docker daemon, and Docker
Buildx with `imagetools inspect`. Keep registry credentials available through
collection and scanning. Each registry lookup has a two-minute timeout. The
live collector has a six-hour safety limit and otherwise uses GitHub runner
process cleanup on cancellation/runner loss; always include the collect step.

Malformed metadata, capture failures, and registry lookup failures make
collection fail. Available references and an error report are still emitted
when collection reaches report generation. The example scanner runs even after
that failure, uploads completed SPDX/CycloneDX SBOMs and `discovery.json`, and
also fails on an incomplete discovery report. Missing/invalid state fails
before outputs are emitted. No discoveries produce an explicit notice and an
empty report, not a claim that unspecified Buildx outputs were discovered.

## Repository integrations and tests

`publish-containers.yml` collects the Buildx metadata for both ACR and GHCR.
`publish-acr-simple.yml` exercises the ordinary Docker push-event path.
Both retain the original all-local-image scanner as a comparison baseline.

```sh
bash .github/actions/discover-pushed-images/test.sh
bash .github/actions/runner-registry-image-sbom/test.sh
```

Tests exercise the actual start/capture/collect scripts with mocked Docker,
including lifecycle cleanup, Docker pushes, Buildx-only pushes, metadata files,
multiple repositories/tags, duplicate evidence, Docker Hub normalization, empty
results, interrupted streams, invalid metadata, registry failures, and wrong-job
state. Scanner tests cover registry-only mode and retained discovery errors.
