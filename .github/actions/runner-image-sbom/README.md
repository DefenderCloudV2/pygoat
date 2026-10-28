# Azure SBOM upload service contract

The action implements a client for a **separately deployed SAS broker**. This
repository does not deploy the broker or create a storage account. An Azure
Function or another HTTPS service can implement the following contract.

## Configuration

Configure all three repository/environment Actions variables:

| Variable | Action input | Meaning |
| --- | --- | --- |
| `SBOM_UPLOAD_SERVICE_URL` | `upload-service-url` | Full HTTPS POST endpoint, for example `https://sbom-service.example.com/v1/uploads`. No query string or embedded credentials. |
| `SBOM_UPLOAD_OIDC_AUDIENCE` | `oidc-audience` | Exact audience the broker accepts, for example `api://sbom-uploads`. |
| `SBOM_STORAGE_ACCOUNT` | `storage-account` | Azure public-cloud account name whose blob host the client permits. |

The calling job needs `permissions: {contents: read, id-token: write}`. All five
integrated image-building jobs already have these permissions. No account key,
pre-generated SAS, or client secret is configured in GitHub.

With all inputs empty, Azure upload is explicitly **skipped**, with a warning,
summary, and `upload-results.json`; GitHub artifact upload still runs. Partial
configuration fails. Once enabled, any authorization, metadata-integrity, or
upload failure fails the action, while completed SBOMs remain downloadable in
the GitHub artifact. Successful scans are uploaded even if another image scan
failed. A scan with no images still uploads its index.

## Request flow

1. Read the generated `index.json` and validate each SBOM's SHA-256 and length.
2. Obtain a fresh GitHub OIDC token for the configured audience for each file.
3. POST its build/image metadata to the broker using that token.
4. PUT the exact file bytes to the returned Azure blob SAS URL.
5. Repeat for each successful SBOM and then `index.json`, which durably captures
   the build metadata and all image scan results alongside the SBOMs.

The OIDC token is sent only to the configured broker. Azure receives only the
SAS, never the OIDC bearer token. Requests reject redirects. Transient HTTP
408/429/500/502/503/504 and network errors get at most three attempts with
backoff, and each request has a 60-second timeout. Authorization failures are
not retried. Each broker POST has a stable `Idempotency-Key` equal to the SHA-256
of its exact request body; the broker must return the same blob destination for
retries of that key.

## POST contract

Headers:

```http
Authorization: Bearer <GitHub OIDC JWT>
Content-Type: application/json
Idempotency-Key: <SHA-256 of request bytes>
```

JSON request shape (hashes and identifiers below are placeholders):

```json
{
  "schema_version": 1,
  "scan_id": "12345678-1234-1234-1234-123456789abc",
  "generated_at": "2026-01-01T00:00:00+00:00",
  "build": {
    "repository": "owner/repository",
    "repository_id": "123",
    "repository_owner_id": "456",
    "sha": "<commit SHA>",
    "ref": "refs/heads/master",
    "workflow": "Publish containers to ACR and GHCR",
    "workflow_ref": "owner/repository/.github/workflows/publish-containers.yml@refs/heads/master",
    "workflow_sha": "<workflow commit SHA>",
    "run_id": "789",
    "run_attempt": "1",
    "job": "publish",
    "event_name": "push",
    "server_url": "https://github.com",
    "run_url": "https://github.com/owner/repository/actions/runs/789",
    "runner": {"os": "Linux", "arch": "X64"}
  },
  "artifact": {
    "name": "sha256-<64 lowercase hex characters>.spdx.json",
    "kind": "sbom",
    "content_type": "application/spdx+json",
    "size_bytes": 12345,
    "sha256": "<SHA-256 of the SBOM bytes>"
  },
  "image": {
    "image_id": "sha256:<local Docker image ID>",
    "status": "success",
    "tags": ["registry.example.com/image:commit"],
    "repo_digests": ["registry.example.com/image@sha256:<manifest digest>"],
    "platform": {"os": "linux", "architecture": "amd64", "variant": null},
    "image_created_at": "<Docker image creation timestamp>",
    "oci_labels": {"org.opencontainers.image.revision": "<commit SHA>"},
    "packages": 42,
    "sbom": "sha256-<64 lowercase hex characters>.spdx.json",
    "sbom_sha256": "<SHA-256 of the SBOM bytes>",
    "sbom_size_bytes": 12345
  }
}
```

For `index.json`, `artifact.kind` is `index`, `content_type` is
`application/json`, and `image` is `null`. The index contains `schema_version`,
`scan_id`, `generated_at`, `build`, and the full `images` array. Absent local
image metadata is `null` or an empty list/object. Only the OCI source, revision,
and version labels are copied, not arbitrary labels or runner environment
variables. The SBOM's own `creationInfo` identifies Syft and its version.

Local Docker image IDs, registry manifest digests, source commits, and SBOM
checksums identify **different things**. Preserve them separately. Build
metadata describes the workflow context; it does not prove image provenance.
Labels and client-supplied fields must not be used as authentication evidence.

Return HTTP **200**:

```json
{
  "upload_url": "https://ACCOUNT.blob.core.windows.net/CONTAINER/BLOB?sv=...&spr=https&sr=b&sp=cw&se=...&sig=..."
}
```

Return 400 for invalid metadata, 401 for an invalid token, and 403 for a valid
identity outside policy. Do not redirect. Do not include secrets in error
messages; the client intentionally reports only HTTP status codes.

## Broker authorization and storage responsibilities

- Verify the JWT signature using GitHub's OIDC discovery/JWKS, pin the issuer
  `https://token.actions.githubusercontent.com`, require the configured audience,
  and validate expiry/not-before and allowed algorithms. Never just decode it.
- Authorize an allowlist of immutable repository/owner IDs, workflow refs,
  branches/tags or environments, and event types. Reject untrusted fork/PR
  contexts unless explicitly intended. This repository uses immutable OIDC
  subjects; do not assume the legacy `repo:owner/name:...` subject shape.
- Compare request repository, commit/ref, run ID/attempt, and workflow identity
  against signed claims. Derive tenant/storage prefixes from verified identity,
  not arbitrary client paths. Job names and image labels are metadata, not
  signed authorization claims.
- Use the broker's managed identity with narrowly scoped Azure RBAC to issue
  a **user-delegation SAS**, rather than exposing storage account keys.
- Return HTTPS-only, single-blob SAS grants (`sr=b`, `spr=https`) with only write
  (`sp=w`) or create/write (`sp=cw`) permission and a short lifetime (for example,
  15 minutes). The client rejects other accounts, container/account-level
  grants, and read/list/delete permissions. Only Azure public-cloud
  `ACCOUNT.blob.core.windows.net` hosts are supported.
- Choose deterministic object paths, for example
  `repository-id/run-id/run-attempt/job/scan-id/artifact-name`. The scan UUID
  separates matrix jobs sharing a job ID. Bind idempotency keys to the verified
  identity, file hash, size, and destination; reject conflicting reuse.
- Validate metadata schemas and enforce quotas. SAS grants themselves cannot
  enforce the advertised content hash or length: validate uploaded blobs against
  the grant metadata server-side, for example from a BlobCreated event, before
  treating them as accepted. A client-reported successful PUT is not a signed
  attestation or proof of trust.
- Redact JWTs and SAS query strings from service/access logs. Do not log request
  authorization headers or return credentials other than the intended blob SAS.

## Azure PUT and retained evidence

The client sends `x-ms-blob-type: BlockBlob`, `x-ms-version: 2023-11-03`,
the content type, and `Content-MD5` for Azure's transport-integrity validation.
`x-ms-meta-sbom_sha256` and `x-ms-meta-scan_id` correlate the blob with the
request and index. Azure must return HTTP **201**.

Repeated PUTs use the same bytes and blob destination, so an ambiguous transient
failure can be retried safely with write permission. The broker should prevent
different content from being granted the same destination.

`upload-results.json` is retained in the **GitHub artifact**, not recursively
uploaded. It records each file's SHA-256, success/failure, and query-free blob
URL on success. It never persists SAS URLs or OIDC tokens. The Azure index
captures scan results, not upload results; failed uploads may leave a partial
set in storage, explicitly reported by the failed job and GitHub evidence.

References:
[GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc),
[Azure Put Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob).
