from contextlib import redirect_stdout
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import scan


OLD = "sha256:" + "0" * 64
FIRST = "sha256:" + "1" * 64
SECOND = "sha256:" + "2" * 64


class ScanTests(unittest.TestCase):
    def setUp(self):
        captured = redirect_stdout(io.StringIO())
        captured.__enter__()
        self.addCleanup(captured.__exit__, None, None, None)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        environment = patch.dict(os.environ, {
            "RUNNER_TEMP": str(self.directory),
            "GITHUB_OUTPUT": str(self.directory / "output"),
            "GITHUB_STEP_SUMMARY": str(self.directory / "summary"),
        })
        environment.start()
        self.addCleanup(environment.stop)
        (self.directory / "baseline.json").write_text(json.dumps([OLD]), encoding="utf-8")

    def fake_run(self, command, **kwargs):
        if command[0] == "docker":
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps([{
                "RepoTags": ["example:latest", "example:commit"],
                "RepoDigests": [],
            }]))
        destination = Path(command[-1].split("=", 1)[1])
        destination.write_text(json.dumps({
            "spdxVersion": "SPDX-2.3", "packages": [{"name": "example"}],
        }), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    def results(self):
        return json.loads(
            (self.directory / "sboms" / "index.json").read_text(encoding="utf-8")
        )["images"]

    def test_snapshot_records_unique_ids_and_isolates_state(self):
        with patch.object(scan, "image_ids", return_value={OLD, FIRST}):
            scan.snapshot()
        directory = Path((self.directory / "output").read_text().strip().split("=", 1)[1])
        self.assertNotEqual(directory, self.directory)
        self.assertEqual(json.loads((directory / "baseline.json").read_text()), [OLD, FIRST])

    def test_inventory_includes_untagged_images_and_deduplicates_tags(self):
        with patch.object(scan.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, stdout=f"{FIRST}\n{FIRST}\n{SECOND}\n",
        )) as run:
            self.assertEqual(scan.image_ids(), {FIRST, SECOND})
        self.assertEqual(
            run.call_args.args[0],
            ["docker", "image", "ls", "--all", "--quiet", "--no-trunc"],
        )

    def test_invalid_inventory_fails(self):
        with patch.object(scan.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, stdout="not-an-image-id\n",
        )):
            with self.assertRaises(ValueError):
                scan.image_ids()

    def test_only_new_ids_are_scanned_once_with_explicit_docker_source(self):
        with patch.object(scan, "image_ids", return_value={OLD, FIRST, SECOND}), patch.object(
            scan.subprocess, "run", side_effect=self.fake_run,
        ) as run:
            self.assertEqual(scan.scan(self.directory, "syft"), 0)
        commands = [call.args[0] for call in run.call_args_list if call.args[0][0] == "syft"]
        self.assertEqual([command[2] for command in commands], [f"docker:{FIRST}", f"docker:{SECOND}"])
        self.assertTrue(all(command[1] == "scan" for command in commands))
        self.assertEqual(len(self.results()), 2)
        for entry in self.results():
            self.assertEqual(entry["tags"], ["example:latest", "example:commit"])
            self.assertEqual(entry["status"], "success")
            self.assertTrue((self.directory / "sboms" / entry["sbom"]).is_file())
            data = (self.directory / "sboms" / entry["sbom"]).read_bytes()
            self.assertEqual(entry["sbom_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(entry["sbom_size_bytes"], len(data))

    def test_build_metadata_is_captured_without_copying_all_environment_variables(self):
        with patch.dict(os.environ, {
            "GITHUB_REPOSITORY": "example/repo", "GITHUB_REPOSITORY_ID": "123",
            "GITHUB_SHA": "a" * 40, "GITHUB_REF": "refs/heads/master",
            "GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "456",
            "GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": "build",
            "PRIVATE_CREDENTIAL": "must-not-be-copied",
        }), patch.object(scan, "image_ids", return_value={OLD}):
            self.assertEqual(scan.scan(self.directory, "syft"), 0)
        index = json.loads((self.directory / "sboms" / "index.json").read_text())
        self.assertEqual(index["schema_version"], 1)
        self.assertEqual(index["build"]["sha"], "a" * 40)
        self.assertEqual(index["build"]["repository_id"], "123")
        self.assertEqual(index["build"]["run_attempt"], "2")
        self.assertEqual(index["build"]["run_url"], "https://github.com/example/repo/actions/runs/456")
        self.assertNotIn("must-not-be-copied", json.dumps(index))
        self.assertEqual(len(index["scan_id"]), 36)

    def test_no_new_images_records_empty_index_without_scanning(self):
        with patch.object(scan, "image_ids", return_value={OLD}), patch.object(
            scan.subprocess, "run",
        ) as run:
            self.assertEqual(scan.scan(self.directory, "syft"), 0)
        run.assert_not_called()
        self.assertEqual(self.results(), [])

    def test_scan_failure_preserves_other_results_and_removes_partial_sbom(self):
        def fail_first(command, **kwargs):
            result = self.fake_run(command, **kwargs)
            if command[:3] == ["syft", "scan", f"docker:{FIRST}"]:
                raise subprocess.CalledProcessError(1, command)
            return result

        with patch.object(scan, "image_ids", return_value={FIRST, SECOND}), patch.object(
            scan.subprocess, "run", side_effect=fail_first,
        ):
            self.assertEqual(scan.scan(self.directory, "syft"), 1)
        self.assertEqual([entry["status"] for entry in self.results()], ["failed", "success"])
        self.assertEqual(len(list((self.directory / "sboms").glob("*.spdx.json"))), 1)

    def test_invalid_sbom_fails(self):
        def invalid_document(command, **kwargs):
            result = self.fake_run(command, **kwargs)
            if command[0] == "syft":
                Path(command[-1].split("=", 1)[1]).write_text("{}", encoding="utf-8")
            return result

        with patch.object(scan, "image_ids", return_value={FIRST}), patch.object(
            scan.subprocess, "run", side_effect=invalid_document,
        ):
            self.assertEqual(scan.scan(self.directory, "syft"), 1)
        self.assertEqual(self.results()[0]["status"], "failed")

    def test_empty_scratch_image_inventory_is_valid(self):
        def no_packages(command, **kwargs):
            result = self.fake_run(command, **kwargs)
            if command[0] == "syft":
                Path(command[-1].split("=", 1)[1]).write_text(
                    '{"spdxVersion":"SPDX-2.3","packages":[]}', encoding="utf-8",
                )
            return result

        with patch.object(scan, "image_ids", return_value={FIRST}), patch.object(
            scan.subprocess, "run", side_effect=no_packages,
        ):
            self.assertEqual(scan.scan(self.directory, "syft"), 0)
        self.assertEqual(self.results()[0]["packages"], 0)

    def test_missing_baseline_does_not_scan_all_runner_images(self):
        (self.directory / "baseline.json").unlink()
        with self.assertRaises(FileNotFoundError), patch.object(
            scan, "image_ids",
        ) as inventory:
            scan.scan(self.directory, "syft")
        inventory.assert_not_called()

    def test_malformed_baseline_fails(self):
        (self.directory / "baseline.json").write_text('["invalid"]', encoding="utf-8")
        with self.assertRaises(ValueError):
            scan.scan(self.directory, "syft")

    def test_docker_failure_is_not_treated_as_no_images(self):
        with patch.object(scan.subprocess, "run", side_effect=subprocess.CalledProcessError(
            1, ["docker", "image", "ls"],
        )):
            with self.assertRaises(subprocess.CalledProcessError):
                scan.image_ids()

    def test_timeout_is_recorded_as_failure(self):
        def timeout(command, **kwargs):
            if command[0] == "syft":
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            return self.fake_run(command, **kwargs)

        with patch.object(scan, "image_ids", return_value={FIRST}), patch.object(
            scan.subprocess, "run", side_effect=timeout,
        ):
            self.assertEqual(scan.scan(self.directory, "syft"), 1)
        self.assertEqual(self.results()[0]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
