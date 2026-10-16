# Container attestations and releases

The new `Container attestation and release` workflow builds this repository's
Dockerfile, uploads two image artifacts, attests one archive, and publishes it
in a GitHub prerelease. Existing workflows are unchanged.

**PyGoat is intentionally vulnerable. Attestation does not make it safe to run
or certify it as vulnerability-free. Use an isolated learning environment.**

## What is being attested?

An attestation is a signed statement binding an artifact's digest to information
about its origin. This workflow uses GitHub Actions OIDC and Sigstore to sign
SLSA build provenance, including the source repository, commit, and workflow.
There is no signing key or extra secret to configure.

The subject here is the exact `pygoat-attested.tar.gz` Docker image archive.
This is a file attestation, not an attestation of an OCI registry manifest.
The image is delivered through Actions artifacts and GitHub Releases, not GHCR.
For registry delivery, a separate workflow would push the image and attest its
registry manifest digest with `subject-name`, `subject-digest`, and
`push-to-registry: true`.

Attestation does not modify an image. The workflow builds once and saves the
same image with two different tags, `pygoat:non-attested` and `pygoat:attested`.
The saved tag changes the archive metadata and therefore its digest, but the
image ID and layers remain identical. This gives a meaningful negative
verification example: the attested archive's bundle does not verify the
non-attested archive.

| Location | Contents |
| --- | --- |
| Actions artifact `container-image-non-attested` | `pygoat-non-attested.tar.gz`, `SHA256SUMS` |
| Actions artifact `container-image-attested` | `pygoat-attested.tar.gz`, `pygoat-attested.sigstore.json`, `SHA256SUMS` |
| GitHub prerelease | The same three files from the attested artifact |

Actions artifacts are retained for 30 days. Release assets remain until deleted.
The artifact upload service's integrity digest is not itself a signed build
provenance attestation.

## Run the workflow

Commit the new workflow before tagging. From the branch containing it, create a
unique tag (replace the example version each time):

```sh
git tag attestation-v0.1.0
git push origin attestation-v0.1.0
gh run list --repo DefenderCloudV2/pygoat --workflow container-attestation-release.yml
gh run watch RUN_ID --repo DefenderCloudV2/pygoat --exit-status
```

A tag push runs the workflow from that tagged commit; it does not require
merging the workflow into the default branch first. The repository's existing
push workflows may also run, independently.

Manual dispatch is also supported, but must target an `attestation-v<version>`
tag, not a branch. GitHub's manual-dispatch UI requires the workflow to exist
on the default branch. A tag push is the bootstrap path for this demo.

The build job needs `contents: read`, `id-token: write`, and
`attestations: write`. The separate release job has `contents: write` and
`attestations: read`, but no OIDC signing permission. Public GitHub.com
repositories support artifact attestations on current GitHub plans; private
repositories require an eligible enterprise plan.

## What to inspect in Actions

1. **Build image archives and attest** builds and exports both archives, checks
   that the image IDs match and archive digests differ, and uploads the baseline.
2. **Attest the downloadable image archive** creates a signed provenance bundle
   and uploads the attestation to GitHub's attestations service.
3. **Preserve and verify the attestation** verifies both via the saved bundle and
   via GitHub's API. It also checks that the baseline fails verification against
   that bundle. The negative test prints an expected verification error.
4. **Verify downloaded image and publish prerelease** downloads the exact
   attested artifact ID from this run into a fresh job, checks the checksum and
   provenance, and only then publishes a prerelease with those same bytes.

Verification restricts the repository, signer workflow, source commit, source
tag, and GitHub-hosted runner. A checksum alone would not prove any of these.
An existing release is never overwritten: rerunning publication for an already
published tag fails. Use a fresh version tag for a new demonstration.

## Download, verify, and load

Install a current GitHub CLI and Docker. Use a fresh download directory, replace
the example tag, and copy the source commit SHA from the release notes:

```sh
gh release download attestation-v0.1.0 --repo DefenderCloudV2/pygoat
gh attestation verify pygoat-attested.tar.gz --repo DefenderCloudV2/pygoat --bundle pygoat-attested.sigstore.json --signer-workflow DefenderCloudV2/pygoat/.github/workflows/container-attestation-release.yml --source-digest SOURCE_COMMIT_SHA --source-ref refs/tags/attestation-v0.1.0 --deny-self-hosted-runners
docker load --input pygoat-attested.tar.gz
docker image inspect pygoat:attested
```

These single-line commands also work in PowerShell. Omit `--bundle` to look up
the attestation using GitHub's API instead. Bundle verification can still need
network access to refresh Sigstore trust material; it is not a guarantee of
fully offline operation. Verify the compressed file unchanged, before loading.

To compare the unsigned example, download the baseline artifact from the same
workflow run:

```sh
gh run download RUN_ID --repo DefenderCloudV2/pygoat --name container-image-non-attested --dir baseline
```

Verify that archive against `pygoat-attested.sigstore.json` using the same
verification policy. It must fail because the subject digest differs.
Changing even one byte in the attested archive also invalidates verification.

## References

- [GitHub artifact attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
- [Build provenance action](https://github.com/actions/attest-build-provenance)
- [GitHub CLI verification options](https://cli.github.com/manual/gh_attestation_verify)
- [SLSA provenance](https://slsa.dev/spec/v1.0/provenance)
