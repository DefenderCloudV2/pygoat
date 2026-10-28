"""Generate one SBOM per new image ID in the job's Docker daemon."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid


def output(name, value):
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(f"{name}={value}\n")


def image_ids():
    result = subprocess.run(
        ["docker", "image", "ls", "--all", "--quiet", "--no-trunc"],
        check=True, capture_output=True, text=True,
    )
    ids = set(result.stdout.splitlines())
    if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", image) for image in ids):
        raise ValueError("Docker returned an invalid image ID")
    return ids


def snapshot():
    baseline = image_ids()
    directory = Path(tempfile.mkdtemp(
        prefix="runner-image-sbom-", dir=os.environ["RUNNER_TEMP"],
    ))
    (directory / "baseline.json").write_text(
        json.dumps(sorted(baseline)), encoding="utf-8",
    )
    output("state-directory", directory)
    print(f"Recorded {len(baseline)} pre-existing Docker image IDs.")


def build_metadata():
    fields = (
        "repository", "repository_id", "repository_owner_id", "sha", "ref",
        "workflow", "workflow_ref", "workflow_sha", "run_id", "run_attempt",
        "job", "event_name", "server_url",
    )
    build = {field: os.environ.get(f"GITHUB_{field.upper()}") for field in fields}
    if all(build[field] for field in ("server_url", "repository", "run_id")):
        build["run_url"] = (
            f"{build['server_url']}/{build['repository']}/actions/runs/{build['run_id']}"
        )
    build["runner"] = {field: os.environ.get(f"RUNNER_{field.upper()}") for field in ("os", "arch")}
    return build


def scan(directory, syft):
    baseline = json.loads((directory / "baseline.json").read_text(encoding="utf-8"))
    if not isinstance(baseline, list) or any(
        not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)
        for image in baseline
    ):
        raise ValueError("Invalid Docker image snapshot")
    images = sorted(image_ids() - set(baseline))
    destination = directory / "sboms"
    destination.mkdir()
    output("artifact-directory", destination)
    results = []
    for image in images:
        filename = f"{image.replace(':', '-')}.spdx.json"
        path = destination / filename
        entry = {"image_id": image, "status": "failed"}
        try:
            inspected = subprocess.run(
                ["docker", "image", "inspect", image],
                check=True, capture_output=True, text=True,
            )
            metadata = json.loads(inspected.stdout)[0]
            entry["tags"] = metadata.get("RepoTags") or []
            entry["repo_digests"] = metadata.get("RepoDigests") or []
            entry["platform"] = {
                field: metadata.get(key)
                for field, key in (("os", "Os"), ("architecture", "Architecture"), ("variant", "Variant"))
            }
            entry["image_created_at"] = metadata.get("Created")
            labels = (metadata.get("Config") or {}).get("Labels") or {}
            entry["oci_labels"] = {
                key: labels[key] for key in (
                    "org.opencontainers.image.source",
                    "org.opencontainers.image.revision",
                    "org.opencontainers.image.version",
                ) if key in labels
            }
            print(f"Generating SBOM for {image}", flush=True)
            subprocess.run(
                [syft, "scan", f"docker:{image}", "--output", f"spdx-json={path}"],
                check=True, timeout=600,
            )
            data = path.read_bytes()
            document = json.loads(data)
            if (
                not isinstance(document, dict)
                or document.get("spdxVersion") != "SPDX-2.3"
                or not isinstance(document.get("packages"), list)
            ):
                raise ValueError("Syft did not produce an SPDX 2.3 package inventory")
            entry.update(status="success", sbom=filename, packages=len(document["packages"]))
            entry.update(sbom_sha256=hashlib.sha256(data).hexdigest(), sbom_size_bytes=len(data))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, ValueError) as error:
            # Keep scanning other images, but fail the step after preserving their results.
            path.unlink(missing_ok=True)
            entry["error"] = str(error)
            print(f"::error::SBOM generation failed for {image}: {error}")
            if isinstance(error, subprocess.CalledProcessError) and error.stderr:
                print(error.stderr)
        results.append(entry)

    (destination / "index.json").write_text(
        json.dumps({
            "schema_version": 1,
            "scan_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "build": build_metadata(),
            "images": results,
        }, indent=2) + "\n", encoding="utf-8",
    )
    succeeded = sum(entry["status"] == "success" for entry in results)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write(
            f"\n## Runner image SBOMs\n\n"
            f"Found {len(images)} new local image IDs; generated {succeeded} SPDX SBOMs.\n"
            "The artifact's `index.json` maps image IDs, tags and registry digests to SBOM files.\n"
        )
    if not images:
        print("::notice::No new local Docker image IDs since the snapshot; index.json is empty.")
    return 0 if succeeded == len(images) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["snapshot", "scan"])
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--syft")
    args = parser.parse_args()
    if args.phase == "snapshot":
        snapshot()
        return 0
    if not args.state_directory or not args.syft:
        parser.error("scan requires --state-directory and --syft")
    return scan(args.state_directory, args.syft)


if __name__ == "__main__":
    raise SystemExit(main())
