# ACR attestation storage and copy experiment

The standalone `Experiment with ACR attestation storage and copying` workflow
tests registry objects rather than assuming that all kinds of metadata travel
together. It reuses the `CONTAINER_AZURE_*` and `CONTAINER_ACR_*` repository
variables and Azure OIDC login from the existing ACR workflows. It does not
modify those workflows, deploy PyGoat, create releases, or publish to GHCR.

Run it on the default branch:

```sh
gh workflow run experiment-acr-attestation-copy.yml --repo DefenderCloudV2/pygoat --ref master
gh run list --repo DefenderCloudV2/pygoat --workflow experiment-acr-attestation-copy.yml
gh run watch RUN_ID --repo DefenderCloudV2/pygoat --exit-status
```

## What it tests

1. Build and push with `docker/build-push-action`, `provenance: true`, and
   `sbom: true`. The image index references both the runnable platform manifest
   and BuildKit attestation manifests. These statements are not cryptographically
   signed by those flags alone.
2. Download the actual index, attestation manifests, and in-toto blobs. Require
   SLSA provenance and an SPDX 2.3 SBOM with packages, both referring to the
   Linux/amd64 platform digest. Extract the SBOM predicate for signing, using
   compact JSON to avoid expanding it past GitHub's 16 MiB signing limit.
   No packages, files, or relationships are removed; an oversized compact
   document fails explicitly rather than silently truncating the inventory.
3. Use `actions/attest-build-provenance` with `push-to-registry: true` to attach
   signed provenance to the root index digest. Use `actions/attest` to attach
   the extracted SBOM as a second signed attestation of that same index.
4. Query the OCI 1.1 referrers API explicitly, at both index and platform
   digests. Inspect each root referrer's manifest and its `subject`. Attaching
   these signatures must not change the image tag's root index digest.
5. Copy to three fresh repositories: `crane copy`, plain `oras copy`, and
   `oras copy --recursive` with the OCI 1.1 referrers API. Inspect the copies.
6. Verify the signed provenance and signed SBOM fetched directly from ACR for
   both source and recursive copy. Enforce this repository, workflow, source
   commit/ref, and GitHub-hosted runner; compare the verified SBOM predicate
   with the actual extracted BuildKit SBOM.

## Expected distinction

| Method | Index-contained BuildKit metadata | External signed referrers |
| --- | --- | --- |
| `crane copy` (whole index, no platform filter) | Preserved | Not copied by this command |
| `oras copy` | Preserved | Not copied without recursion |
| `oras copy --recursive` | Preserved | Preserved |

The workflow fails if this matrix does not match the actual objects. It records
tool versions because copy behavior and artifact layouts can evolve. It does
not generalize the result to every crane/cosign version or every registry.
Legacy cosign digest-derived tags are not the same as OCI referrers; this
experiment uses GitHub's signed Sigstore bundles and the actual OCI 1.1 API,
not a tag fallback.

The signed attestations refer to the root index; BuildKit's embedded statements
refer to the runnable platform manifest. Newer BuildKit versions may also expose
their embedded manifests as referrers of that platform. The evidence captures
both attachment points instead of conflating them.

Copying preserves the source build identity, not a new destination build.
Signature verification authenticates provenance; labels alone do not. The
workflow does not claim that the unsigned BuildKit statements or the SBOM prove
the application is secure.

## Evidence and retained images

Each run writes under
`<ACR-login-server>/pygoat-metadata-experiment/<run-id>-<attempt>/`:

- `source:experiment`
- `crane:experiment`
- `oras-plain:experiment`
- `oras-recursive:experiment`

Fresh repositories avoid confusing existing digest-linked referrers with copied
ones. No production tags are overwritten. These images remain in ACR until
explicitly deleted and consume registry storage.

Download `acr-attestation-copy-<run-id>-<attempt>` from the Actions run.
It contains `comparison.md`, `comparison.json`, raw manifests, index/platform
referrer responses, actual predicate JSON, image configuration, signed bundles,
verification results, and tool versions. Actions evidence retention is 30 days.
Partial evidence is uploaded on failures, and failed checks remain failures.

The job also pulls the source image by its published digest and runs the shared
runner-image SBOM action as a final step. Its separate `runner-image-sboms-*`
artifact contains unsigned Syft SBOMs and build/image metadata, with optional
OIDC/SAS upload to Azure Storage when configured. This does not replace or
modify the BuildKit SBOM or signed attestations used by the copy experiment.
See the [upload service contract](../.github/actions/runner-image-sbom/README.md).

**PyGoat is intentionally vulnerable. This experiment publishes images but does
not run the application or expose any endpoint.**

## References

- [BuildKit attestation storage](https://docs.docker.com/build/metadata/attestations/attestation-storage/)
- [ORAS copy and recursive referrers](https://oras.land/docs/commands/oras_cp/)
- [GitHub attestation action](https://github.com/actions/attest)
- [crane copy](https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane_copy.md)
