"""Submit an immutable image's CycloneDX SBOM without exposing credentials."""

import argparse
import base64
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import http.client
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


API_BASE = "https://aspm-externalapi-stg-eus.internal.mdatp.microsoft-int.com"
AUDIENCE = "api://aspm-scanning-sbom-staging"
BLOB_PREFIX = (
    "https://aspmsarifstgeus.blob.core.windows.net/sarif/sbom/"
    "2f80fb48-3d73-471d-8aaf-80af69ffd2f4/1356696257/"
)
IMAGE_PATTERN = r"ghcr\.io/defendercloudv2/pygoat@sha256:[0-9a-f]{64}"
MAX_BYTES = 10485760


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class TransportError(RuntimeError):
    pass


def request(method, url, headers=None, data=None, timeout=90):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        response = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError, ValueError, http.client.HTTPException):
        raise TransportError("HTTP transport failed; request details withheld.") from None
    try:
        with response:
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise TransportError("HTTP response exceeded the diagnostic size limit.")
            return response.code, response.headers, body
    except (OSError, ValueError, http.client.HTTPException):
        raise TransportError("HTTP response could not be read; details withheld.") from None


def object_json(raw):
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Response is not a valid JSON object; contents withheld.") from None
    if not isinstance(result, dict):
        raise ValueError("Response is not a JSON object; contents withheld.")
    return result


def mask(value):
    # Escape workflow-command control characters before masking untrusted values.
    escaped = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::add-mask::" + escaped, flush=True)


def oidc_token():
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    credential = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or not credential:
        raise ValueError("GitHub Actions OIDC environment is missing or invalid.")
    query = [(k, v) for k, v in urllib.parse.parse_qsl(parsed.query) if k != "audience"]
    query.append(("audience", AUDIENCE))
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
    status, _, raw = request(
        "GET", url, {"Authorization": "Bearer " + credential}, timeout=30
    )
    if status != 200:
        raise RuntimeError("GitHub OIDC acquisition failed: HTTP %s." % status)
    token = object_json(raw).get("value")
    if not isinstance(token, str) or len(token.split(".")) != 3:
        raise ValueError("GitHub returned an invalid OIDC token.")
    mask(token)
    try:
        payload = token.split(".")[1]
        claims = object_json(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        expected = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": AUDIENCE,
            "repository": "DefenderCloudV2/pygoat",
            "repository_id": "1356696257",
            "repository_owner_id": "324759237",
        }
        now = datetime.now(timezone.utc).timestamp()
        if any(claims.get(key) != value for key, value in expected.items()):
            raise ValueError()
        if not all(type(claims.get(key)) in (int, float) for key in ("nbf", "exp")):
            raise ValueError()
        if not claims["nbf"] <= now < claims["exp"]:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ValueError("OIDC payload does not match the staging claims/lifetime contract.") from None
    print(
        "OIDC payload matches staging issuer, audience, repository and owner IDs, "
        "and current lifetime. Signature verification remains the API's responsibility."
    )
    return token


def validate_sbom(raw, image):
    if not re.fullmatch(IMAGE_PATTERN, image):
        raise ValueError("Expected the lowercase GHCR image reference with its real SHA256 digest.")
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("SBOM must contain between 1 byte and 10 MiB.")
    try:
        document = object_json(raw.decode("utf-8"))
    except UnicodeError:
        raise ValueError("SBOM must be UTF-8 JSON.") from None
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") not in (
        "1.4", "1.5", "1.6", "1.7"
    ):
        raise ValueError("Expected supported CycloneDX JSON 1.4 through 1.7.")
    stack = [(document, 0)]
    while stack:
        value, depth = stack.pop()
        if isinstance(value, (dict, list)):
            if depth >= 64:
                raise ValueError("SBOM exceeds the JSON depth limit.")
            children = value.values() if isinstance(value, dict) else value
            stack.extend((child, depth + 1) for child in children)

    refs = set()

    def reference(value):
        if not isinstance(value, str) or not value or len(value) > 512:
            raise ValueError("SBOM contains an invalid or oversized reference.")
        return value

    metadata = document.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Invalid SBOM metadata structure.")
    root = metadata.get("component", {})
    components = document.get("components", [])
    if not isinstance(root, dict) or not isinstance(components, list):
        raise ValueError("Invalid SBOM component structure.")
    pending = list(components)
    nested_root = root.get("components", [])
    if not isinstance(nested_root, list):
        raise ValueError("Invalid nested SBOM components.")
    pending.extend(nested_root)
    if "bom-ref" in root:
        refs.add(reference(root["bom-ref"]))
    count = 0
    while pending:
        component = pending.pop()
        count += 1
        if count > 2000 or not isinstance(component, dict):
            raise ValueError("SBOM exceeds component limits or contains invalid components.")
        if "bom-ref" in component:
            ref = reference(component["bom-ref"])
            if ref in refs:
                raise ValueError("SBOM component references must be unique.")
            refs.add(ref)
        nested = component.get("components", [])
        if not isinstance(nested, list):
            raise ValueError("Invalid nested SBOM components.")
        pending.extend(nested)
    dependencies = document.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("Invalid SBOM dependency structure.")
    dependency_refs = set()
    total = 0
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("Invalid SBOM dependency entry.")
        ref = reference(dependency.get("ref"))
        if ref in dependency_refs:
            raise ValueError("SBOM dependency references must be unique.")
        dependency_refs.add(ref)
        targets = dependency.get("dependsOn", [])
        if not isinstance(targets, list):
            raise ValueError("Invalid SBOM dependency targets.")
        total += 1 + len(targets)
        if total > 20000:
            raise ValueError("SBOM exceeds the dependency-reference limit.")
        for target in targets:
            reference(target)


def safe_response(result):
    """Only allowlisted identifiers/counts leave the response's private boundary."""
    safe = {}
    for key in ("uploadId", "ingestionId", "traceId"):
        value = result.get(key)
        if isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9:_-]{1,128}", value):
            safe[key] = value
    if result.get("status") in ("submitted", "not_submitted"):
        safe["status"] = result["status"]
    for key in ("packageCount", "edgeCount", "unknownDependencyCount", "skippedPackageCount"):
        value = result.get(key)
        if type(value) is int and value >= 0:
            safe[key] = value
    upstream = result.get("ekgResponse")
    if isinstance(upstream, dict) and type(upstream.get("statusCode")) is int:
        safe["ekgStatusCode"] = upstream["statusCode"]
    safe["warningPresent"] = bool(result.get("warning"))
    skipped = result.get("skippedPackages", [])
    reasons = {}
    if isinstance(skipped, list):
        for item in skipped:
            reason = item.get("reasonCode") if isinstance(item, dict) else None
            if reason in ("InvalidPurl", "MissingPackageVersion", "ConflictingPackageVersion"):
                reasons[reason] = reasons.get(reason, 0) + 1
    safe["skippedReasons"] = reasons
    return safe


def safe_http_diagnostics(headers, body):
    diagnostics = {}
    try:
        diagnostics.update(safe_response(object_json(body)))
    except ValueError:
        pass
    challenge = headers.get("WWW-Authenticate", "")
    match = re.search(r'\berror="([^"]+)"', challenge)
    if match and match[1] in ("invalid_token", "invalid_request", "insufficient_scope"):
        diagnostics["authenticationError"] = match[1]
    categories = {
        "audience": "audience", "issuer": "issuer", "signature": "signature",
        "expired": "lifetime", "lifetime": "lifetime", "signing key": "signing_key",
    }
    hints = sorted({category for word, category in categories.items() if word in challenge.lower()})
    if hints:
        diagnostics["authenticationHints"] = hints
    if headers.get("Date"):
        try:
            diagnostics["serverDate"] = parsedate_to_datetime(headers["Date"]).isoformat()
        except (ValueError, TypeError, OverflowError):
            pass
    return diagnostics


def evidence(path, result):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True), flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as output:
            output.write("\n### Cloud SBOM submission\n\n```json\n")
            output.write(json.dumps(result, indent=2) + "\n```\n")
            output.write("\nSubmission does not confirm downstream graph materialization.\n")


def preflight():
    try:
        status, _, _ = request("POST", API_BASE + "/api/aspm/scanning/sbom/uploads", timeout=30)
    except TransportError:
        raise RuntimeError(
            "Staging API is unreachable from this runner. An approved private-network "
            "runner is required; no upload was attempted."
        ) from None
    if status != 401:
        raise RuntimeError("Expected authenticated staging route (HTTP 401); got HTTP %s." % status)
    print("Staging route reachable; unauthenticated request correctly returned HTTP 401.")


def submit(sbom_path, image, evidence_path):
    if sbom_path.stat().st_size > MAX_BYTES:
        raise ValueError("SBOM exceeds 10 MiB.")
    raw = sbom_path.read_bytes()
    validate_sbom(raw, image)
    state = {"imageId": image, "phase": "allocation", "acceptance": "not_attempted"}
    evidence(evidence_path, state)
    token = oidc_token()
    status, headers, body = request(
        "POST", API_BASE + "/api/aspm/scanning/sbom/uploads",
        {"Authorization": "Bearer " + token},
    )
    if status != 201:
        state.update(safe_http_diagnostics(headers, body))
        state["httpStatus"] = status
        evidence(evidence_path, state)
        raise RuntimeError("Upload allocation failed: HTTP %s." % status)
    upload = object_json(body)
    upload_url = upload.get("uploadUrl")
    if isinstance(upload_url, str):
        mask(upload_url)
    try:
        upload_id = str(uuid.UUID(upload["uploadId"]))
        expected = BLOB_PREFIX + upload_id + ".json"
        expiry = datetime.fromisoformat(upload["expiresAt"].replace("Z", "+00:00"))
        url = urllib.parse.urlsplit(upload_url)
        if (
            upload["blobUrl"] != expected
            or urllib.parse.urlunsplit(url._replace(query="")) != expected
            or not url.query
            or expiry <= datetime.now(timezone.utc)
        ):
            raise ValueError()
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ValueError("Invalid or expired upload allocation; details withheld.") from None
    state.update(uploadId=upload_id, phase="blob_upload")
    evidence(evidence_path, state)
    status, headers, _ = request(
        "PUT", upload_url, {"x-ms-blob-type": "BlockBlob", "Content-Type": "application/json"},
        raw, timeout=120,
    )
    if status != 201:
        state["httpStatus"] = status
        evidence(evidence_path, state)
        raise RuntimeError("Blob upload failed: HTTP %s." % status)
    etag = headers.get("ETag", "")
    if len(etag) > 128 or not re.fullmatch(r'"[^"\x00-\x20\x7f]+"', etag):
        raise ValueError("Blob upload did not return a strong quoted ETag.")
    payload = json.dumps({"blobUrl": expected, "eTag": etag, "imageId": image}).encode("utf-8")
    token = oidc_token()
    state.update(phase="completion", acceptance="unknown")
    evidence(evidence_path, state)
    try:
        status, _, body = request(
            "POST", API_BASE + "/api/aspm/scanning/sbom/uploads/" + upload_id + "/complete",
            {"Authorization": "Bearer " + token, "Content-Type": "application/json"}, payload,
        )
    except TransportError:
        raise RuntimeError(
            "Completion transport failed. Acceptance is unknown; reconcile using "
            "saved correlation IDs. Do not retry automatically."
        ) from None
    state["httpStatus"] = status
    try:
        result = object_json(body)
    except ValueError:
        evidence(evidence_path, state)
        raise RuntimeError(
            "Completion returned non-JSON data. Acceptance is unknown; do not retry automatically."
        ) from None
    state.update(safe_response(result))
    state["uploadId"] = upload_id
    if status == 200 and result.get("status") == "submitted":
        state["acceptance"] = "submitted"
    elif status in (400, 401, 403, 404, 409, 413, 422):
        state["acceptance"] = "not_submitted"
    evidence(evidence_path, state)
    if state["acceptance"] != "submitted":
        raise RuntimeError(
            "SBOM completion failed; inspect saved correlation IDs before any retry."
        )
    if state.get("skippedPackageCount", 0) > 0 or state["warningPresent"]:
        print("::warning::Partial snapshot accepted; see counts and reason codes. Do not resubmit automatically.")
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        if args.preflight:
            preflight()
        else:
            if not all((args.sbom, args.image, args.evidence)):
                parser.error("--sbom, --image and --evidence are required")
            submit(args.sbom, args.image, args.evidence)
    except (ValueError, RuntimeError) as error:
        print("::error::" + str(error), file=sys.stderr)
        return 1
    except (OSError, RecursionError, AttributeError, TypeError):
        print("::error::Local SBOM/evidence processing failed; details withheld.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
