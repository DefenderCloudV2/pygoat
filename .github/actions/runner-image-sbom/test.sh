#!/usr/bin/env bash
set -euo pipefail

action="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/action.yml"
root=$(mktemp -d)
trap 'rm -r -- "$root"' EXIT
mkdir "$root/bin" "$root/runner with spaces"
export RUNNER_TEMP="$root/runner with spaces"
export PATH="$root/bin:$PATH"
export TEST_IMAGES="$root/images" TEST_SCANS="$root/scans"
export GITHUB_OUTPUT="$root/output" GITHUB_STEP_SUMMARY="$root/summary"
export GITHUB_REPOSITORY=example/repo GITHUB_REPOSITORY_ID=123 GITHUB_RUN_ID=456
export GITHUB_RUN_ATTEMPT=2 GITHUB_JOB=build GITHUB_SERVER_URL=https://github.com
export PRIVATE_CREDENTIAL=must-not-be-copied
old="sha256:$(printf '%064d' 0)"
first="sha256:$(printf '%064d' 1)"
second="sha256:$(printf '%064d' 2)"

# Exercise the actual inline Bash blocks without adding a YAML dependency.
for step in validate snapshot scan; do
  awk -v step="$step" '
    {sub(/\r$/, "")}
    $0 == "      id: " step {found=1}
    found && /^      run: \|$/ {script=1; next}
    script && /^        / {print substr($0, 9); next}
    script && NF {exit}
  ' "$action" > "$root/$step.sh"
  test -s "$root/$step.sh"
  bash -n "$root/$step.sh"
done

cat > "$root/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "image ls") test "${FAIL_LIST:-0}" = 0; cat "$TEST_IMAGES" ;;
  "image inspect")
    test "${FAIL_INSPECT:-}" != "$3"
    jq -n '[{
      RepoTags: ["example:ci", "example:alias"], RepoDigests: [],
      Os: "linux", Architecture: "amd64", Created: "2026-01-01T00:00:00Z",
      Config: {Labels: {"org.opencontainers.image.revision": "commit", "private-label": "omit-me"}}
    }]' ;;
  *) echo "Unexpected Docker command" >&2; exit 90 ;;
esac
MOCK

cat > "$root/bin/syft" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
test "$1" = scan
test "$3" = --output
printf '%s\n' "$2" >> "$TEST_SCANS"
printf '%s\n' "${MOCK_SBOM}" > "${4#spdx-json=}"
test "$2" != "${FAIL_SYFT:-}"
MOCK
chmod +x "$root/bin/docker" "$root/bin/syft"
export SYFT_COMMAND="$root/bin/syft"

snapshot() {
  unset FAIL_SYFT FAIL_INSPECT FAIL_LIST
  export MOCK_SBOM='{"spdxVersion":"SPDX-2.3","packages":[{"name":"fixture"}]}'
  printf '%s\n' "$old" "$old" > "$TEST_IMAGES"
  : > "$GITHUB_OUTPUT"
  : > "$TEST_SCANS"
  PHASE=snapshot STATE_DIRECTORY="" bash "$root/validate.sh"
  bash "$root/snapshot.sh"
  STATE_DIRECTORY=$(sed -n 's/^state-directory=//p' "$GITHUB_OUTPUT")
  export STATE_DIRECTORY
  test "$(wc -l < "$STATE_DIRECTORY/before.txt")" -eq 1
  PHASE=scan bash "$root/validate.sh"
}

snapshot
printf '%s\n' "$second" "$old" "$first" "$first" > "$TEST_IMAGES"
bash "$root/scan.sh"
index="$STATE_DIRECTORY/sboms/index.json"
test "$(wc -l < "$TEST_SCANS")" -eq 2
jq -e --arg first "$first" --arg second "$second" '
  .schema_version == 1 and .build.repository == "example/repo" and
  .build.repository_id == "123" and .build.run_attempt == "2" and
  .build.run_url == "https://github.com/example/repo/actions/runs/456" and
  [.images[].image_id] == [$first, $second] and
  all(.images[]; .status == "success" and .packages == 1 and
    .tags == ["example:ci", "example:alias"] and .platform.architecture == "amd64" and
    .oci_labels == {"org.opencontainers.image.revision": "commit"})
' "$index" > /dev/null
! grep -qE 'must-not-be-copied|omit-me' "$index"
for image in "$first" "$second"; do
  file="$STATE_DIRECTORY/sboms/${image/:/-}.spdx.json"
  jq -e --arg image "$image" --arg hash "$(sha256sum "$file" | cut -d ' ' -f 1)" \
    --argjson size "$(wc -c < "$file")" \
    'any(.images[]; .image_id == $image and .sbom_sha256 == $hash and .sbom_size_bytes == $size)' "$index" > /dev/null
done

snapshot
bash "$root/scan.sh" > "$root/no-images.log"
jq -e '.images == []' "$STATE_DIRECTORY/sboms/index.json" > /dev/null
test ! -s "$TEST_SCANS"
grep -q '::notice::No new local Docker image IDs' "$root/no-images.log"

for failure in syft inspect invalid-json; do
  snapshot
  printf '%s\n' "$first" "$second" > "$TEST_IMAGES"
  case "$failure" in
    syft) export FAIL_SYFT="docker:$first" ;;
    inspect) export FAIL_INSPECT="$first" ;;
    invalid-json) export MOCK_SBOM='{}' ;;
  esac
  if bash "$root/scan.sh" > "$root/failure.log" 2>&1; then
    echo "Expected failure for $failure" >&2
    exit 1
  fi
  test ! -e "$STATE_DIRECTORY/sboms/${first/:/-}.spdx.json"
  jq -e '.images[0].status == "failed"' "$STATE_DIRECTORY/sboms/index.json" > /dev/null
  grep -q '::error::SBOM generation failed' "$root/failure.log"
  if [[ "$failure" != invalid-json ]]; then
    jq -e '.images[1].status == "success"' "$STATE_DIRECTORY/sboms/index.json" > /dev/null
  fi
done

snapshot
printf '%s\n' "$first" > "$TEST_IMAGES"
export MOCK_SBOM='{"spdxVersion":"SPDX-2.3","packages":[]}'
bash "$root/scan.sh"
jq -e '.images[0].packages == 0' "$STATE_DIRECTORY/sboms/index.json" > /dev/null

snapshot
printf '%s\n' invalid > "$TEST_IMAGES"
if bash "$root/scan.sh" > /dev/null 2>&1; then exit 1; fi
if bash "$root/snapshot.sh" > /dev/null 2>&1; then exit 1; fi
printf '%s\n' "$old" > "$TEST_IMAGES"
printf '%s\n' invalid > "$STATE_DIRECTORY/before.txt"
if bash "$root/scan.sh" > /dev/null 2>&1; then exit 1; fi

snapshot
export FAIL_LIST=1
if bash "$root/snapshot.sh" > /dev/null 2>&1; then exit 1; fi
if bash "$root/scan.sh" > /dev/null 2>&1; then exit 1; fi
if PHASE=wrong bash "$root/validate.sh" > /dev/null 2>&1; then exit 1; fi
if PHASE=scan STATE_DIRECTORY="$root/missing" bash "$root/validate.sh" > /dev/null 2>&1; then exit 1; fi
echo "PASS: inline action commands, image discovery, metadata, checksums, and failure handling."
