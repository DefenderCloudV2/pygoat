import copy
import unittest

from acr_attestation_copy import validate_copies, validate_predicates


class EvidenceTests(unittest.TestCase):
    def snapshots(self):
        baseline = {
            "digest": "sha256:index",
            "platform_digest": "sha256:platform",
            "embedded_digests": ["sha256:buildkit"],
            "predicate_types": ["https://slsa.dev/provenance/v0.2", "https://spdx.dev/Document"],
            "sbom_packages": 20,
            "referrer_digests": [],
        }
        snapshots = {
            name: copy.deepcopy(baseline)
            for name in ("source-before", "source-signed", "crane", "oras-plain", "oras-recursive")
        }
        for name in ("source-signed", "oras-recursive"):
            snapshots[name]["referrer_digests"] = ["sha256:signature1", "sha256:signature2"]
        return snapshots

    def test_expected_copy_matrix(self):
        validate_copies(self.snapshots())

    def test_rejects_lost_metadata_and_unexpected_referrers(self):
        for name, field, value in (
            ("crane", "embedded_digests", []),
            ("oras-plain", "digest", "sha256:changed"),
            ("oras-recursive", "referrer_digests", ["sha256:signature1"]),
            ("crane", "referrer_digests", ["sha256:signature1"]),
            ("source-before", "referrer_digests", ["sha256:old"]),
        ):
            with self.subTest(name=name, field=field):
                snapshots = self.snapshots()
                snapshots[name][field] = value
                with self.assertRaises(ValueError):
                    validate_copies(snapshots)

    def statements(self):
        return [
            {
                "predicateType": predicate_type,
                "subject": [{"digest": {"sha256": "platform"}}],
                "predicate": {"spdxVersion": "SPDX-2.3", "packages": [{"name": "Django"}]},
            }
            for predicate_type in ("https://slsa.dev/provenance/v0.2", "https://spdx.dev/Document")
        ]

    def test_validates_actual_predicates(self):
        sbom = validate_predicates(self.statements(), "sha256:platform")
        self.assertEqual(sbom["packages"][0]["name"], "Django")

    def test_rejects_missing_predicate(self):
        with self.assertRaises(ValueError):
            validate_predicates(self.statements()[:1], "sha256:platform")

    def test_rejects_wrong_subject(self):
        with self.assertRaises(ValueError):
            validate_predicates(self.statements(), "sha256:other")

    def test_rejects_empty_sbom(self):
        statements = self.statements()
        statements[1]["predicate"]["packages"] = []
        with self.assertRaises(ValueError):
            validate_predicates(statements, "sha256:platform")


if __name__ == "__main__":
    unittest.main()
