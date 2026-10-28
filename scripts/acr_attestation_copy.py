"""Inspect actual registry objects; fail if the copy experiment loses metadata."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def save_sbom(path, sbom):
    # Whitespace alone can push BuildKit's full file inventory over the signing limit.
    payload = json.dumps(sbom, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    require(len(payload) <= 16 * 1024 * 1024, "Complete SBOM exceeds GitHub's 16 MiB signing limit")
    path.write_bytes(payload)


def fetch_json(command, path, digest=None):
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE)
    if digest is not None:
        actual = "sha256:" + hashlib.sha256(result.stdout).hexdigest()
        require(actual == digest, f"Digest mismatch for {path}: {actual} != {digest}")
    value = json.loads(result.stdout)
    path.write_bytes(result.stdout)
    return value


def validate_predicates(statements, platform_digest):
    require(
        any(s["predicateType"].startswith("https://slsa.dev/provenance/") for s in statements),
        "BuildKit provenance missing",
    )
    sboms = [s for s in statements if s["predicateType"].startswith("https://spdx.dev/Document")]
    require(len(sboms) == 1, "Expected one platform SPDX statement")
    for statement in statements:
        require(
            any(s["digest"].get("sha256") == platform_digest.split(":")[1]
                for s in statement["subject"]),
            "BuildKit statement is not bound to the platform manifest",
        )
    sbom = sboms[0]["predicate"]
    require(sbom["spdxVersion"] == "SPDX-2.3", "Expected SPDX 2.3")
    require(len(sbom["packages"]) > 0, "SBOM contains no packages")
    return sbom


def inspect(image, output):
    output.mkdir(parents=True, exist_ok=True)
    repository, digest = image.split("@", 1)
    index = fetch_json(["crane", "manifest", image], output / "index.json", digest=digest)
    platforms = [
        d for d in index["manifests"]
        if d.get("platform", {}).get("os") == "linux"
        and d.get("platform", {}).get("architecture") == "amd64"
    ]
    require(len(platforms) == 1, "Expected one Linux/amd64 platform")
    platform_digest = platforms[0]["digest"]
    embedded = [
        d for d in index["manifests"]
        if d.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest"
    ]
    require(embedded, "No BuildKit attestation descriptors in image index")
    statements = []
    for number, descriptor in enumerate(embedded):
        require(
            descriptor["annotations"]["vnd.docker.reference.digest"] == platform_digest,
            "Attestation descriptor targets the wrong platform",
        )
        manifest = fetch_json(
            ["crane", "manifest", f"{repository}@{descriptor['digest']}"],
            output / f"buildkit-manifest-{number}.json",
            digest=descriptor["digest"],
        )
        for layer_number, layer in enumerate(manifest["layers"]):
            require(layer["mediaType"] == "application/vnd.in-toto+json", "Unexpected attestation layer")
            statement = fetch_json(
                ["crane", "blob", f"{repository}@{layer['digest']}"],
                output / f"buildkit-statement-{number}-{layer_number}.json",
                digest=layer["digest"],
            )
            require(
                layer.get("annotations", {}).get("in-toto.io/predicate-type") == statement["predicateType"],
                "Predicate annotation disagrees with statement",
            )
            statements.append(statement)
    sbom = validate_predicates(statements, platform_digest)
    save_sbom(output / "sbom.spdx.json", sbom)
    fetch_json(
        ["crane", "config", f"{repository}@{platform_digest}"],
        output / "image-config.json",
    )
    # Force the actual OCI 1.1 API: do not silently use the referrers-tag fallback.
    root_referrers = fetch_json(
        ["oras", "discover", "--distribution-spec", "v1.1-referrers-api", "--format", "json", image],
        output / "index-referrers.json",
    )
    fetch_json(
        ["oras", "discover", "--distribution-spec", "v1.1-referrers-api", "--format", "json",
         f"{repository}@{platform_digest}"],
        output / "platform-referrers.json",
    )
    referrers = root_referrers["referrers"]
    for number, referrer in enumerate(referrers):
        manifest = fetch_json(
            ["crane", "manifest", f"{repository}@{referrer['digest']}"],
            output / f"signed-referrer-{number}.json",
            digest=referrer["digest"],
        )
        require(manifest["subject"]["digest"] == digest, "Referrer subject is not the root index")
    summary = {
        "image": image,
        "digest": digest,
        "platform_digest": platform_digest,
        "embedded_digests": sorted(d["digest"] for d in embedded),
        "predicate_types": sorted(s["predicateType"] for s in statements),
        "sbom_packages": len(sbom["packages"]),
        "referrer_digests": sorted(d["digest"] for d in referrers),
    }
    save(output / "summary.json", summary)
    return summary


def validate_copies(snapshots):
    before = snapshots["source-before"]
    signed = snapshots["source-signed"]
    require(not before["referrer_digests"], "Source index already had external referrers before signing")
    require(len(signed["referrer_digests"]) == 2, "Expected signed provenance and SBOM referrers")
    for name, snapshot in snapshots.items():
        for field in ("digest", "platform_digest", "embedded_digests", "predicate_types", "sbom_packages"):
            require(snapshot[field] == before[field], f"{name}: changed {field}")
    for name in ("crane", "oras-plain"):
        require(not snapshots[name]["referrer_digests"], f"{name}: unexpectedly copied external referrers")
    require(
        snapshots["oras-recursive"]["referrer_digests"] == signed["referrer_digests"],
        "Recursive ORAS copy did not preserve both signed referrers",
    )


def compare(output):
    names = ("source-before", "source-signed", "crane", "oras-plain", "oras-recursive")
    snapshots = {
        name: json.loads((output / name / "summary.json").read_text(encoding="utf-8"))
        for name in names
    }
    validate_copies(snapshots)
    save(output / "comparison.json", snapshots)
    lines = [
        "## ACR attestation storage and copy experiment",
        "",
        "| Snapshot | Embedded attestation manifests | SPDX packages | External index referrers |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name, snapshot in snapshots.items():
        lines.append(
            f"| {name} | {len(snapshot['embedded_digests'])} | "
            f"{snapshot['sbom_packages']} | {len(snapshot['referrer_digests'])} |"
        )
    lines.extend([
        "",
        "All copies preserve the root index digest, platform digest, and embedded predicates.",
        "Plain crane/ORAS copy preserves index descendants, not external signed referrers.",
        "ORAS recursive copy also preserves both external referrers via the OCI 1.1 API.",
        "BuildKit statements target the platform manifest; signed statements target the root index.",
        "",
    ])
    for name, snapshot in snapshots.items():
        lines.append(f"- {name}: `{snapshot['image']}`")
    (output / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_parser = commands.add_parser("inspect")
    inspect_parser.add_argument("--image", required=True)
    inspect_parser.add_argument("--output", required=True, type=Path)
    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "inspect":
        inspect(args.image, args.output)
    else:
        compare(args.output)
