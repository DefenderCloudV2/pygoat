import contextlib
import base64
import copy
import http.client
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse

import submit_sbom as client


IMAGE = "ghcr.io/defendercloudv2/pygoat@sha256:" + "a" * 64
UPLOAD_ID = "11111111-1111-4111-8111-111111111111"
BLOB = client.BLOB_PREFIX + UPLOAD_ID + ".json"
SECRET = "private-response-marker"
DOCUMENT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"type": "container", "bom-ref": "root", "name": "pygoat"}},
    "components": [{"type": "library", "bom-ref": "requests", "purl": "pkg:pypi/requests@2.32.3"}],
    "dependencies": [{"ref": "root", "dependsOn": ["requests"]}],
}


class SubmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sbom = Path(self.temp.name) / "sbom.cdx.json"
        self.sbom.write_text(json.dumps(DOCUMENT), encoding="utf-8")
        self.output = Path(self.temp.name) / "response.json"
        self.console = io.StringIO()
        self.addCleanup(patch.stopall)
        patch.dict("os.environ", {"GITHUB_STEP_SUMMARY": ""}).start()
        patch("submit_sbom.mask").start()

    def responses(self, completion=None):
        allocation = {
            "uploadId": UPLOAD_ID, "blobUrl": BLOB,
            "uploadUrl": BLOB + "?sig=" + SECRET, "expiresAt": "2099-01-01T00:00:00+00:00",
        }
        result = {
            "status": "submitted", "ingestionId": UPLOAD_ID, "traceId": "trace-123",
            "packageCount": 1, "edgeCount": 1, "unknownDependencyCount": 0,
            "skippedPackageCount": 0, "warning": None,
            "ekgResponse": {"statusCode": 202, "body": SECRET, "headers": {"Secret": [SECRET]}},
        }
        return [
            (201, {}, json.dumps(allocation).encode()),
            (201, {"ETag": '"0x123"'}, b""),
            completion or (200, {}, json.dumps(result).encode()),
        ]

    def run_submit(self, responses):
        with patch("submit_sbom.oidc_token", side_effect=["first", "fresh"]) as tokens:
            with patch("submit_sbom.request", side_effect=responses) as http:
                with contextlib.redirect_stdout(self.console):
                    result = client.submit(self.sbom, IMAGE, self.output)
        return result, http, tokens

    def test_exact_sequence_digest_etag_and_secret_boundary(self):
        result, http, tokens = self.run_submit(self.responses())
        self.assertEqual(tokens.call_count, 2)
        self.assertEqual([call.args[0] for call in http.call_args_list], ["POST", "PUT", "POST"])
        allocation, put, complete = http.call_args_list
        self.assertEqual(len(allocation.args), 3)  # No allocation request body.
        self.assertNotIn("Authorization", put.args[2])
        self.assertEqual(put.args[3], self.sbom.read_bytes())
        self.assertEqual(complete.args[2]["Authorization"], "Bearer fresh")
        self.assertEqual(json.loads(complete.args[3]), {
            "blobUrl": BLOB, "eTag": '"0x123"', "imageId": IMAGE,
        })
        self.assertEqual(result["acceptance"], "submitted")
        self.assertEqual(result["ekgStatusCode"], 202)
        self.assertNotIn(SECRET, self.output.read_text() + self.console.getvalue())

    def test_ambiguous_completion_is_never_retried(self):
        for failure in (
            client.TransportError("transport"),
            (504, {}, b'{"ingestionId":"' + UPLOAD_ID.encode() + b'"}'),
            (502, {}, b'{"ekgResponse":{"statusCode":403}}'),
            (200, {}, b"not-json"),
        ):
            with self.subTest(failure=failure):
                responses = self.responses()[:2] + [failure]
                with patch("submit_sbom.oidc_token", return_value="token"):
                    with patch("submit_sbom.request", side_effect=responses) as http:
                        with contextlib.redirect_stdout(self.console):
                            with self.assertRaises(RuntimeError):
                                client.submit(self.sbom, IMAGE, self.output)
                self.assertEqual(http.call_count, 3)
                self.assertEqual(json.loads(self.output.read_text())["acceptance"], "unknown")

    def test_partial_submission_warns_without_retry_or_raw_warning(self):
        result = {
            "status": "submitted", "skippedPackageCount": 1, "warning": SECRET,
            "skippedPackages": [{"reasonCode": "InvalidPurl", "explanation": SECRET}],
        }
        state, http, _ = self.run_submit(self.responses((200, {}, json.dumps(result).encode())))
        self.assertEqual(state["skippedReasons"], {"InvalidPurl": 1})
        self.assertIn("::warning::", self.console.getvalue())
        self.assertNotIn(SECRET, self.console.getvalue())
        self.assertEqual(http.call_count, 3)

    def test_definite_rejection_and_non_json_failure(self):
        for response, acceptance in (
            ((422, {}, b'{"status":"not_submitted"}'), "not_submitted"),
            ((403, {}, b"forbidden"), "unknown"),
        ):
            with self.assertRaises(RuntimeError):
                self.run_submit(self.responses(response))
            self.assertEqual(json.loads(self.output.read_text())["acceptance"], acceptance)

    def test_invalid_allocation_and_etag_stop_before_completion(self):
        for edit in ("url", "expiry", "etag"):
            responses = self.responses()
            if edit == "etag":
                responses[1] = (201, {"ETag": 'W/"weak"'}, b"")
            else:
                allocation = json.loads(responses[0][2])
                allocation["uploadUrl" if edit == "url" else "expiresAt"] = (
                    "https://example.com/?sig=secret" if edit == "url" else "2000-01-01T00:00:00Z"
                )
                responses[0] = (201, {}, json.dumps(allocation).encode())
            with patch("submit_sbom.oidc_token", return_value="token"):
                with patch("submit_sbom.request", side_effect=responses) as http:
                    with contextlib.redirect_stdout(self.console):
                        with self.assertRaises(ValueError):
                            client.submit(self.sbom, IMAGE, self.output)
            self.assertLess(http.call_count, 3)

    def test_oidc_exact_audience_and_no_token_logging(self):
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": client.AUDIENCE, "repository": "DefenderCloudV2/pygoat",
            "repository_id": "1356696257", "repository_owner_id": "324759237",
            "nbf": 0, "exp": 4070908800,
        }
        token = "header." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode() + ".signature"
        with patch.dict("os.environ", {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.com/token?a=1&audience=old",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-credential",
        }):
            with patch("submit_sbom.request", return_value=(
                200, {}, json.dumps({"value": token}).encode()
            )) as http:
                with contextlib.redirect_stdout(self.console):
                    self.assertEqual(client.oidc_token(), token)
        parsed = urllib.parse.urlsplit(http.call_args.args[1])
        self.assertEqual(urllib.parse.parse_qs(parsed.query)["audience"], [client.AUDIENCE])
        self.assertEqual(http.call_args.args[2]["Authorization"], "Bearer request-credential")

    def test_oidc_rejects_mismatched_claims(self):
        with patch.dict("os.environ", {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.com/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "credential",
        }):
            with patch("submit_sbom.request", return_value=(200, {}, b'{"value":"a.e30.c"}')):
                with self.assertRaisesRegex(ValueError, "claims/lifetime"):
                    client.oidc_token()

    def test_authentication_diagnostics_are_allowlisted(self):
        result = client.safe_http_diagnostics({
            "WWW-Authenticate": 'Bearer error="invalid_token", error_description="signature ' + SECRET + '"',
            "Date": "Tue, 10 Nov 2026 16:37:46 GMT",
        }, b'{"traceId":"trace-123","detail":"' + SECRET.encode() + b'"}')
        self.assertEqual(result["authenticationError"], "invalid_token")
        self.assertEqual(result["authenticationHints"], ["signature"])
        self.assertEqual(result["traceId"], "trace-123")
        self.assertNotIn(SECRET, json.dumps(result))

    def test_preflight_requires_authenticated_route_and_handles_network_failure(self):
        for response in ((401, {}, b""), (200, {}, b""), client.TransportError("secret")):
            with patch("submit_sbom.request", side_effect=[response]):
                with contextlib.redirect_stdout(self.console):
                    if isinstance(response, tuple) and response[0] == 401:
                        client.preflight()
                    else:
                        with self.assertRaises(RuntimeError):
                            client.preflight()

    def test_redirects_cannot_forward_credentials(self):
        self.assertIsNone(client.NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere"))

    def test_transport_failure_hides_url(self):
        with patch("urllib.request.OpenerDirector.open", side_effect=urllib.error.URLError(SECRET)):
            with self.assertRaises(client.TransportError) as error:
                client.request("PUT", "https://example.com/?sig=" + SECRET)
        self.assertNotIn(SECRET, str(error.exception))

    def test_incomplete_response_hides_details(self):
        with patch("urllib.request.OpenerDirector.open", side_effect=http.client.IncompleteRead(b"secret")):
            with self.assertRaises(client.TransportError):
                client.request("POST", "https://example.com/")

    def test_allocation_and_put_failures_do_not_complete(self):
        for responses in (
            [(403, {}, SECRET.encode())],
            [(201, {}, b"not-json")],
            self.responses()[:1] + [(409, {}, SECRET.encode())],
        ):
            with patch("submit_sbom.oidc_token", return_value="token"):
                with patch("submit_sbom.request", side_effect=responses) as http:
                    with contextlib.redirect_stdout(self.console):
                        with self.assertRaises((ValueError, RuntimeError)):
                            client.submit(self.sbom, IMAGE, self.output)
            self.assertLess(http.call_count, 3)
            self.assertNotIn(SECRET, self.console.getvalue())


class ValidationTests(unittest.TestCase):
    def validate(self, document):
        client.validate_sbom(json.dumps(document).encode(), IMAGE)

    def test_supported_versions(self):
        for version in ("1.4", "1.5", "1.6", "1.7"):
            self.validate(dict(DOCUMENT, specVersion=version))

    def test_invalid_digest_format_size_and_reference(self):
        for raw, image in (
            (json.dumps(DOCUMENT).encode(), IMAGE.upper()),
            (json.dumps(DOCUMENT).encode(), IMAGE.replace("@", ":latest@")),
            (b"{}", IMAGE), (b"[", IMAGE), (b"x" * (client.MAX_BYTES + 1), IMAGE),
        ):
            with self.assertRaises(ValueError):
                client.validate_sbom(raw, image)
        for change in (
            {"specVersion": "1.8"},
            {"metadata": []},
            {"components": [{"bom-ref": "root"}]},
            {"components": [{"bom-ref": "a" * 513}]},
            {"components": [{}] * 2001},
            {"dependencies": [{"ref": "root", "dependsOn": ["x"] * 20000}]},
            {"dependencies": [{"ref": "x"}, {"ref": "x"}]},
            {"dependencies": [{"ref": "x", "dependsOn": ["x" * 513]}]},
        ):
            with self.subTest(change=list(change)):
                with self.assertRaises(ValueError):
                    self.validate(dict(DOCUMENT, **change))

    def test_exact_limits_are_accepted(self):
        document = dict(DOCUMENT, components=[{}] * 2000)
        document["dependencies"] = [{"ref": "a" * 512, "dependsOn": ["x" * 512] * 19999}]
        self.validate(document)
        raw = json.dumps(DOCUMENT).encode()
        client.validate_sbom(raw + b" " * (client.MAX_BYTES - len(raw)), IMAGE)
        document = copy.deepcopy(DOCUMENT)
        current = document
        for _ in range(63):
            current["nested"] = {}
            current = current["nested"]
        self.validate(document)

    def test_depth_and_nested_components(self):
        document = copy.deepcopy(DOCUMENT)
        document["metadata"]["component"]["components"] = [{"bom-ref": "root"}]
        with self.assertRaises(ValueError):
            self.validate(document)
        document = copy.deepcopy(DOCUMENT)
        current = document
        for _ in range(65):
            current["nested"] = {}
            current = current["nested"]
        with self.assertRaises(ValueError):
            self.validate(document)

    def test_safe_response_excludes_untrusted_fields(self):
        self.assertEqual(client.safe_response({
            "traceId": "::error::bad\n", "packageCount": True, "warning": SECRET,
            "ekgResponse": {"body": SECRET}, "arbitrary": SECRET,
        }), {"warningPresent": True, "skippedReasons": {}})


if __name__ == "__main__":
    unittest.main()
