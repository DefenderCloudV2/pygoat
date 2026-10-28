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
export UNTAGGED_IMAGE="$second"

# Exercise the actual inline Bash block without adding a YAML dependency.
awk '
  {sub(/\r$/, "")}
  $0 == "      id: scan" {found=1}
  found && /^      run: \|$/ {script=1; next}
  script && /^        / {print substr($0, 9); next}
  script && NF {exit}
' "$action" > "$root/scan.sh"
test -s "$root/scan.sh"
bash -n "$root/scan.sh"

cat > "$root/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "image ls")
    test "$*" = "image ls --all --quiet --no-trunc"
    test "${FAIL_LIST:-0}" = 0
    cat "$TEST_IMAGES" ;;
  "image inspect")
    test "${FAIL_INSPECT:-}" != "$3"
    jq -n --arg image "$3" --arg untagged "$UNTAGGED_IMAGE" '[{
      RepoTags: (if $image == $untagged then [] else ["example:ci", "example:alias"] end), RepoDigests: [],
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

prepare() {
  unset FAIL_SYFT FAIL_INSPECT FAIL_LIST
  export MOCK_SBOM='{"spdxVersion":"SPDX-2.3","packages":[{"name":"fixture"}]}'
  : > "$TEST_IMAGES"
  : > "$GITHUB_OUTPUT"
  : > "$TEST_SCANS"
}

artifact_directory() {
  sed -n 's/^artifact-directory=//p' "$GITHUB_OUTPUT"
}

prepare
printf '%s\n' "$second" "$old" "$first" "$first" "$old" > "$TEST_IMAGES"
bash "$root/scan.sh"
destination=$(artifact_directory)
index="$destination/index.json"
test "$(wc -l < "$TEST_SCANS")" -eq 3
jq -e --arg old "$old" --arg first "$first" --arg second "$second" '
  .schema_version == 1 and .build.repository == "example/repo" and
  .build.repository_id == "123" and .build.run_attempt == "2" and
  .build.run_url == "https://github.com/example/repo/actions/runs/456" and
  [.images[].image_id] == [$old, $first, $second] and
  .images[0].tags == ["example:ci", "example:alias"] and
  .images[2].tags == [] and
  all(.images[]; .status == "success" and .packages == 1 and
    .platform.architecture == "amd64" and
    .oci_labels == {"org.opencontainers.image.revision": "commit"})
' "$index" > /dev/null
! grep -qE 'must-not-be-copied|omit-me' "$index"
for image in "$old" "$first" "$second"; do
  grep -qx "docker:$image" "$TEST_SCANS"
  file="$destination/${image/:/-}.spdx.json"
  jq -e --arg image "$image" --arg hash "$(sha256sum "$file" | cut -d ' ' -f 1)" \
    --argjson size "$(wc -c < "$file")" \
    'any(.images[]; .image_id == $image and .sbom_sha256 == $hash and .sbom_size_bytes == $size)' "$index" > /dev/null
done

prepare
bash "$root/scan.sh" > "$root/no-images.log"
jq -e '.images == []' "$(artifact_directory)/index.json" > /dev/null
test ! -s "$TEST_SCANS"
grep -q '::notice::No local Docker images found' "$root/no-images.log"

for failure in syft inspect invalid-json; do
  prepare
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
  destination=$(artifact_directory)
  test ! -e "$destination/${first/:/-}.spdx.json"
  jq -e '.images[0].status == "failed"' "$destination/index.json" > /dev/null
  grep -q '::error::SBOM generation failed' "$root/failure.log"
  if [[ "$failure" != invalid-json ]]; then
    jq -e '.images[1].status == "success"' "$destination/index.json" > /dev/null
  fi
done

prepare
printf '%s\n' "$first" > "$TEST_IMAGES"
export MOCK_SBOM='{"spdxVersion":"SPDX-2.3","packages":[]}'
bash "$root/scan.sh"
jq -e '.images[0].packages == 0' "$(artifact_directory)/index.json" > /dev/null

prepare
printf '%s\n' invalid > "$TEST_IMAGES"
if bash "$root/scan.sh" > /dev/null 2>&1; then exit 1; fi
test ! -s "$GITHUB_OUTPUT"

prepare
export FAIL_LIST=1
if bash "$root/scan.sh" > /dev/null 2>&1; then exit 1; fi
test ! -s "$GITHUB_OUTPUT"
echo "PASS: all local images (including pre-existing and untagged), deduplication, metadata, checksums, and failure handling."
