"""Upload SBOMs and their build/image index through an OIDC-authenticated SAS broker."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class UploadError(Exception):
    """An error that is safe to print without credentials or response bodies."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def https_url(value):
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password or parsed.fragment
            or parsed.port not in (None, 443)
            or any(char.isspace() or ord(char) < 32 for char in value)
        ):
            raise ValueError()
    except (ValueError, TypeError):
        raise UploadError("Expected an HTTPS URL without user info or a fragment.") from None
    return parsed


def request(method, url, headers, data=None, expected=200):
    opener = build_opener(NoRedirect())
    for attempt in range(3):
        try:
            with opener.open(Request(url, data=data, headers=headers, method=method), timeout=60) as response:
                if response.status != expected:
                    raise UploadError(f"{method} returned unexpected HTTP {response.status}.")
                body = response.read(1024 * 1024 + 1)
                if len(body) > 1024 * 1024:
                    raise UploadError(f"{method} response exceeded the size limit.")
                return body
        except HTTPError as error:
            status = error.code
            error.close()
            if attempt == 2 or status not in (408, 429, 500, 502, 503, 504):
                raise UploadError(f"{method} failed with HTTP {status}.") from None
        except (URLError, OSError):
            if attempt == 2:
                raise UploadError(f"{method} failed due to a network error.") from None
        time.sleep(2 ** attempt)


def json_object(data):
    try:
        result = json.loads(data)
    except (ValueError, UnicodeError):
        raise UploadError("Invalid JSON response or metadata.") from None
    if not isinstance(result, dict):
        raise UploadError("Expected a JSON object.")
    return result


def oidc_token(audience):
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not url or not bearer:
        raise UploadError("GitHub OIDC is unavailable; the job requires id-token: write.")
    parsed = https_url(url)
    query = [(key, value) for key, value in parse_qsl(parsed.query) if key != "audience"]
    query.append(("audience", audience))
    url = urlunsplit(parsed._replace(query=urlencode(query)))
    token = json_object(request("GET", url, {"Authorization": f"Bearer {bearer}"})).get("value")
    if not isinstance(token, str) or not token or any(char.isspace() for char in token):
        raise UploadError("GitHub did not return a valid OIDC token.")
    return token


def blob_url(value, account):
    parsed = https_url(value)
    query = dict(parse_qsl(parsed.query))
    if (
        parsed.hostname != f"{account}.blob.core.windows.net"
        or len(parsed.path.strip("/").split("/")) < 2
        or not query.get("sig") or not query.get("se")
        or query.get("sr") != "b" or query.get("spr") != "https"
        or "w" not in query.get("sp", "") or set(query["sp"]) - set("cw")
    ):
        raise UploadError("Service returned an invalid blob-scoped, write-only SAS URL for the configured account.")
    return urlunsplit(parsed._replace(query=""))


def upload(directory, service, audience, account):
    if not service:
        if audience or account:
            raise UploadError("Upload configuration is incomplete: upload-service-url is missing.")
        return {"status": "skipped", "reason": "Azure upload is not configured.", "files": []}
    if https_url(service).query:
        raise UploadError("The service URL must not contain query parameters.")
    if not audience or not re.fullmatch(r"[a-z0-9]{3,24}", account):
        raise UploadError("Configure oidc-audience and a valid storage-account when enabling Azure upload.")

    index_data = (directory / "index.json").read_bytes()
    index = json_object(index_data)
    if (
        index.get("schema_version") != 1 or not isinstance(index.get("build"), dict)
        or not isinstance(index.get("images"), list) or not isinstance(index.get("scan_id"), str)
        or not re.fullmatch(r"[0-9a-f-]{36}", index["scan_id"])
    ):
        raise UploadError("Invalid SBOM index schema.")
    files = []
    for image in index["images"]:
        if image["status"] != "success":
            continue
        name = image["sbom"]
        if not re.fullmatch(r"sha256-[0-9a-f]{64}\.spdx\.json", name):
            raise UploadError("Invalid SBOM filename in the index.")
        data = (directory / name).read_bytes()
        if len(data) != image["sbom_size_bytes"] or hashlib.sha256(data).hexdigest() != image["sbom_sha256"]:
            raise UploadError("SBOM bytes no longer match the index checksum.")
        files.append((name, data, image))
    files.append(("index.json", index_data, None))

    results = []
    for name, data, image in files:
        digest = hashlib.sha256(data).hexdigest()
        result = {"name": name, "sha256": digest, "status": "failed"}
        payload = {
            "schema_version": 1, "scan_id": index["scan_id"],
            "generated_at": index["generated_at"], "build": index["build"],
            "artifact": {
                "name": name, "kind": "sbom" if image else "index",
                "content_type": "application/spdx+json" if image else "application/json",
                "size_bytes": len(data), "sha256": digest,
            },
            "image": image,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            token = oidc_token(audience)
            grant = json_object(request("POST", service, {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Idempotency-Key": hashlib.sha256(encoded).hexdigest(),
            }, encoded))
            sas = grant.get("upload_url")
            if not isinstance(sas, str):
                raise UploadError("Service response is missing upload_url.")
            destination = blob_url(sas, account)
            request("PUT", sas, {
                "Content-Type": payload["artifact"]["content_type"],
                "Content-MD5": base64.b64encode(hashlib.md5(data, usedforsecurity=False).digest()).decode("ascii"),
                "x-ms-blob-type": "BlockBlob",
                "x-ms-version": "2023-11-03",
                "x-ms-meta-sbom_sha256": digest,
                "x-ms-meta-scan_id": index["scan_id"],
            }, data, expected=201)
            result.update(status="success", blob_url=destination)
        except UploadError as error:
            result["error"] = str(error)
            print(f"::error::Azure upload failed for {name}: {error}")
        results.append(result)
    return {
        "status": "success" if all(item["status"] == "success" for item in results) else "failed",
        "files": results,
    }


def main():
    directory = Path(os.environ["ARTIFACT_DIRECTORY"])
    try:
        result = upload(
            directory, os.environ.get("UPLOAD_SERVICE_URL", ""),
            os.environ.get("OIDC_AUDIENCE", ""), os.environ.get("STORAGE_ACCOUNT", ""),
        )
    except UploadError as error:
        result = {"status": "failed", "reason": str(error), "files": []}
        print(f"::error::Azure SBOM upload failed: {error}")
    except (OSError, KeyError, TypeError, ValueError):
        result = {"status": "failed", "reason": "Unable to read valid SBOM upload metadata.", "files": []}
        print("::error::Unable to read valid SBOM upload metadata.")
    (directory / "upload-results.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8",
    )
    if result["status"] == "skipped":
        print("::warning::Azure upload is not configured; retaining SBOMs as GitHub artifacts only.")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        successful = sum(item["status"] == "success" for item in result["files"])
        summary.write(
            f"\n### Azure SBOM upload\n\nStatus: **{result['status']}**. "
            f"Uploaded {successful}/{len(result['files'])} files.\n"
        )
        if result["status"] == "skipped":
            summary.write("Configure the SAS broker to enable Azure upload; GitHub artifacts are still retained.\n")
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
