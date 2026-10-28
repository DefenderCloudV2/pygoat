import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import upload


SERVICE = "https://sbom-service.example.invalid/v1/uploads"
ACCOUNT = "sbomteststorage"
AUDIENCE = "api://sbom-uploads"
NAME = "sha256-" + "a" * 64 + ".spdx.json"


def sas_url(name=NAME):
    return (
        f"https://{ACCOUNT}.blob.core.windows.net/sboms/{name}"
        "?sv=2023-11-03&sr=b&spr=https&sp=cw&se=2099-01-01T00%3A00%3A00Z&sig=test-signature"
    )


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.stdout = io.StringIO()
        capture = redirect_stdout(self.stdout)
        capture.__enter__()
        self.addCleanup(capture.__exit__, None, None, None)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        environment = patch.dict(os.environ, {
            "ARTIFACT_DIRECTORY": str(self.directory),
            "GITHUB_STEP_SUMMARY": str(self.directory / "summary"),
            "UPLOAD_SERVICE_URL": SERVICE,
            "OIDC_AUDIENCE": AUDIENCE,
            "STORAGE_ACCOUNT": ACCOUNT,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example.invalid/token?existing=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-runner-credential",
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.data = b'{"spdxVersion":"SPDX-2.3","packages":[]}'
        (self.directory / NAME).write_bytes(self.data)
        self.index = {
            "schema_version": 1,
            "scan_id": "12345678-1234-1234-1234-123456789abc",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "build": {
                "repository": "example/repo", "repository_id": "123",
                "sha": "b" * 40, "ref": "refs/heads/master",
                "run_id": "456", "run_attempt": "1", "job": "build",
                "workflow_ref": "example/repo/.github/workflows/build.yml@refs/heads/master",
            },
            "images": [{
                "image_id": "sha256:" + "a" * 64, "status": "success", "sbom": NAME,
                "tags": ["example:ci"], "repo_digests": ["example@sha256:" + "c" * 64],
                "platform": {"os": "linux", "architecture": "amd64", "variant": None},
                "sbom_sha256": hashlib.sha256(self.data).hexdigest(), "sbom_size_bytes": len(self.data),
            }],
        }
        self.write_index()
        self.calls = []

    def write_index(self):
        (self.directory / "index.json").write_text(json.dumps(self.index), encoding="utf-8")

    def fake_request(self, method, url, headers, data=None, expected=200):
        self.calls.append((method, url, headers, data, expected))
        if method == "GET":
            return b'{"value":"test-oidc-token"}'
        if method == "POST":
            payload = json.loads(data)
            return json.dumps({"upload_url": sas_url(payload["artifact"]["name"])}).encode()
        return b""

    def run_upload(self):
        return upload.upload(self.directory, SERVICE, AUDIENCE, ACCOUNT)

    def test_uploads_sbom_and_index_with_metadata_hashes_and_no_bearer_to_storage(self):
        with patch.object(upload, "request", side_effect=self.fake_request):
            result = self.run_upload()
        self.assertEqual(result["status"], "success")
        self.assertEqual([entry["name"] for entry in result["files"]], [NAME, "index.json"])
        gets = [call for call in self.calls if call[0] == "GET"]
        self.assertEqual(len(gets), 2)
        self.assertEqual(parse_qs(urlsplit(gets[0][1]).query)["audience"], [AUDIENCE])
        posts = [call for call in self.calls if call[0] == "POST"]
        for _, _, headers, data, _ in posts:
            payload = json.loads(data)
            self.assertEqual(headers["Authorization"], "Bearer test-oidc-token")
            self.assertEqual(headers["Idempotency-Key"], hashlib.sha256(data).hexdigest())
            self.assertEqual(payload["build"], self.index["build"])
            self.assertEqual(payload["scan_id"], self.index["scan_id"])
        self.assertEqual(json.loads(posts[0][3])["image"], self.index["images"][0])
        puts = [call for call in self.calls if call[0] == "PUT"]
        for _, _, headers, data, expected in puts:
            self.assertNotIn("Authorization", headers)
            self.assertEqual(headers["x-ms-blob-type"], "BlockBlob")
            self.assertEqual(headers["x-ms-meta-sbom_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(
                headers["Content-MD5"],
                base64.b64encode(hashlib.md5(data, usedforsecurity=False).digest()).decode(),
            )
            self.assertEqual(expected, 201)
        self.assertEqual(puts[0][3], self.data)
        self.assertEqual(json.loads(puts[1][3]), self.index)
        self.assertNotIn("sig=", json.dumps(result))
        self.assertNotIn("test-oidc-token", json.dumps(result))

    def test_unconfigured_upload_is_explicit_and_does_not_request_oidc(self):
        with patch.object(upload, "request") as request, patch.dict(os.environ, {
            "UPLOAD_SERVICE_URL": "", "OIDC_AUDIENCE": "", "STORAGE_ACCOUNT": "",
        }):
            self.assertEqual(upload.main(), 0)
        request.assert_not_called()
        result = json.loads((self.directory / "upload-results.json").read_text())
        self.assertEqual(result["status"], "skipped")
        self.assertIn("::warning::", self.stdout.getvalue())

    def test_incomplete_configuration_fails(self):
        for service, audience, account in [
            ("", AUDIENCE, ACCOUNT), (SERVICE, "", ACCOUNT), (SERVICE, AUDIENCE, ""),
            ("http://service.invalid", AUDIENCE, ACCOUNT),
            (SERVICE + "?credential=not-allowed", AUDIENCE, ACCOUNT),
        ]:
            with self.subTest(service=service, audience=audience, account=account):
                with self.assertRaises(upload.UploadError), patch.object(upload, "request") as request:
                    upload.upload(self.directory, service, audience, account)
                request.assert_not_called()

    def test_rejects_wrong_hosts_protocols_and_overprivileged_sas(self):
        invalid = [
            sas_url().replace("https:", "http:"),
            sas_url().replace(ACCOUNT, "otheraccount"),
            sas_url().replace(".blob.core.windows.net", ".blob.core.windows.net.evil.invalid"),
            sas_url().replace("https://", "https://user:password@"),
            sas_url() + "#fragment",
            sas_url().replace("sr=b", "sr=c"),
            sas_url().replace("sp=cw", "sp=rcwdl"),
            sas_url().replace("spr=https", "spr=https,http"),
            sas_url().replace("sig=test-signature", "sig="),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(upload.UploadError):
                upload.blob_url(value, ACCOUNT)

    def test_rejects_invalid_grant_without_uploading(self):
        def bad_grant(method, *args, **kwargs):
            if method == "POST":
                return b'{"upload_url":"https://attacker.invalid/file?sig=test-signature"}'
            return self.fake_request(method, *args, **kwargs)

        with patch.object(upload, "request", side_effect=bad_grant):
            self.assertEqual(self.run_upload()["status"], "failed")
        self.assertFalse(any(call[0] == "PUT" for call in self.calls))
        self.assertNotIn("test-signature", self.stdout.getvalue())

    def test_missing_oidc_permission_fails(self):
        with patch.dict(os.environ, {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": ""}):
            with self.assertRaisesRegex(upload.UploadError, "id-token: write"):
                upload.oidc_token(AUDIENCE)

    def test_checksum_mismatch_fails_before_network_access(self):
        (self.directory / NAME).write_bytes(b"changed")
        with patch.object(upload, "request") as request, self.assertRaisesRegex(
            upload.UploadError, "checksum",
        ):
            self.run_upload()
        request.assert_not_called()

    def test_path_traversal_in_index_is_rejected(self):
        self.index["images"][0]["sbom"] = "../outside.json"
        self.write_index()
        with self.assertRaisesRegex(upload.UploadError, "filename"):
            self.run_upload()

    def test_partial_failure_does_not_prevent_index_upload(self):
        def fail_one(method, url, *args, **kwargs):
            if method == "PUT" and NAME in url:
                raise upload.UploadError("PUT failed with HTTP 403.")
            return self.fake_request(method, url, *args, **kwargs)

        with patch.object(upload, "request", side_effect=fail_one):
            self.assertEqual(upload.main(), 1)
        result = json.loads((self.directory / "upload-results.json").read_text())
        self.assertEqual([entry["status"] for entry in result["files"]], ["failed", "success"])
        self.assertNotIn("test-signature", json.dumps(result) + self.stdout.getvalue())
        self.assertNotIn("test-oidc-token", json.dumps(result) + self.stdout.getvalue())

    def test_empty_scan_still_uploads_index(self):
        self.index["images"] = []
        self.write_index()
        with patch.object(upload, "request", side_effect=self.fake_request):
            result = self.run_upload()
        self.assertEqual([entry["name"] for entry in result["files"]], ["index.json"])

    def test_failed_scan_entries_are_preserved_but_not_uploaded_as_sboms(self):
        self.index["images"].append({"image_id": "sha256:" + "d" * 64, "status": "failed"})
        self.write_index()
        with patch.object(upload, "request", side_effect=self.fake_request):
            result = self.run_upload()
        self.assertEqual(len(result["files"]), 2)
        index_put = [call for call in self.calls if call[0] == "PUT"][-1]
        self.assertEqual(len(json.loads(index_put[3])["images"]), 2)

    def test_retries_transient_http_error_without_changing_put_body(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 201
        response.read.return_value = b""
        opener = MagicMock()
        opener.open.side_effect = [HTTPError(sas_url(), 503, "secret", {}, None), response]
        with patch.object(upload, "build_opener", return_value=opener), patch.object(upload.time, "sleep"):
            upload.request("PUT", sas_url(), {}, self.data, expected=201)
        self.assertEqual(opener.open.call_count, 2)
        for call in opener.open.call_args_list:
            self.assertEqual(call.args[0].data, self.data)

    def test_http_errors_are_redacted_and_auth_failures_are_not_retried(self):
        opener = MagicMock()
        opener.open.side_effect = HTTPError(sas_url(), 403, "test-signature", {}, None)
        with patch.object(upload, "build_opener", return_value=opener):
            with self.assertRaises(upload.UploadError) as caught:
                upload.request("PUT", sas_url(), {}, self.data, expected=201)
        self.assertEqual(str(caught.exception), "PUT failed with HTTP 403.")
        self.assertEqual(opener.open.call_count, 1)

    def test_network_errors_have_bounded_retries_and_redacted_messages(self):
        opener = MagicMock()
        opener.open.side_effect = URLError(sas_url())
        with patch.object(upload, "build_opener", return_value=opener), patch.object(upload.time, "sleep"):
            with self.assertRaises(upload.UploadError) as caught:
                upload.request("PUT", sas_url(), {}, self.data, expected=201)
        self.assertEqual(str(caught.exception), "PUT failed due to a network error.")
        self.assertEqual(opener.open.call_count, 3)

    def test_redirect_handler_refuses_credential_forwarding(self):
        self.assertIsNone(upload.NoRedirect().redirect_request(
            None, None, 307, "", {}, "https://attacker.invalid",
        ))

    def test_malformed_response_is_redacted(self):
        with self.assertRaises(upload.UploadError) as caught:
            upload.json_object(b"not-json test-signature")
        self.assertNotIn("test-signature", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
