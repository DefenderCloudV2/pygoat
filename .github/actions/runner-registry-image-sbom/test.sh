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
registry="registry.example/test@$first"
mirror="mirror.example/test@$first"
export UNTAGGED_IMAGE="$second" REGISTRY_IMAGE_ID="$first"

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
# No pull, inspect, or build-cache commands are allowed.
test "$*" = "image ls --all --quiet --no-trunc"
test "${FAIL_LIST:-0}" = 0
cat "$TEST_IMAGES"
MOCK

cat > "$root/bin/syft" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
test "$1" = scan
source="$2"
shift 2
printf '%s\n' "$source" >> "$TEST_SCANS"
if [[ "$source" == registry:* ]]; then
  test "$1" = --platform
  test "$2" = "$REGISTRY_PLATFORM"
  shift 2
  image="$REGISTRY_IMAGE_ID"
else
  image="${source#docker:}"
fi
image="${MOCK_IMAGE_ID:-$image}"
test "$1" = --output
printf '%s\n' "$MOCK_SBOM" > "${2#spdx-json=}"
test "$3" = --output
jq -n --arg image "$image" --arg untagged "$UNTAGGED_IMAGE" \
  --argjson invalid "${INVALID_METADATA:-false}" '{
    source: {type: "image", metadata: {
      imageID: (if $invalid then "invalid" else $image end),
      tags: (if $image == $untagged then [] else ["example:ci", "example:alias"] end),
      repoDigests: [], manifestDigest: $image, os: "linux", architecture: "amd64",
      config: ({created: "2026-01-01T00:00:00Z", config: {Env: ["SECRET=omit-me"]}} | tojson | @base64),
      labels: {"org.opencontainers.image.revision": "commit", "private-label": "omit-me"}
    }}
  }' > "${4#syft-json=}"
test "$source" != "${FAIL_SYFT:-}"
MOCK
chmod +x "$root/bin/docker" "$root/bin/syft"
export SYFT_COMMAND="$root/bin/syft"

prepare() {
  unset FAIL_SYFT FAIL_LIST INVALID_METADATA MOCK_IMAGE_ID
  export REGISTRY_IMAGES="" REGISTRY_PLATFORM=linux/amd64
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
REGISTRY_IMAGES=$(printf '  %s \r\n\n%s\n%s\n' "$registry" "$mirror" "$registry")
export REGISTRY_IMAGES
bash "$root/scan.sh"
destination=$(artifact_directory)
index="$destination/index.json"
test "$(wc -l < "$TEST_SCANS")" -eq 5
jq -e --arg old "$old" --arg first "$first" --arg second "$second" \
  --arg registry "$registry" --arg mirror "$mirror" '
  .schema_version == 1 and .build.repository == "example/repo" and
  .build.repository_id == "123" and .build.run_attempt == "2" and
  .build.run_url == "https://github.com/example/repo/actions/runs/456" and
  [.images[] | select(.source.type == "docker") | .image_id] == [$old, $first, $second] and
  .images[0].tags == ["example:ci", "example:alias"] and .images[2].tags == [] and
  [.images[] | select(.source.type == "registry") | .source.reference] == [$mirror, $registry] and
  all(.images[] | select(.source.type == "registry");
    .source.requested_platform == "linux/amd64" and .repo_digests == [.source.reference]) and
  all(.images[]; .status == "success" and .packages == 1 and
    .platform.architecture == "amd64" and .image_created_at == "2026-01-01T00:00:00Z" and
    .oci_labels == {"org.opencontainers.image.revision": "commit"}) and
  ([.images[].sbom] | unique | length) == 5
' "$index" > /dev/null
! grep -qE 'must-not-be-copied|omit-me' "$index"
test "$(find "$destination" -type f | wc -l)" -eq 6
while IFS= read -r filename; do
  file="$destination/$filename"
  jq -e --arg filename "$filename" --arg hash "$(sha256sum "$file" | cut -d ' ' -f 1)" \
    --argjson size "$(wc -c < "$file")" \
    'any(.images[]; .sbom == $filename and .sbom_sha256 == $hash and .sbom_size_bytes == $size)' "$index" > /dev/null
done < <(jq -r '.images[].sbom' "$index" | tr -d '\r')

prepare
printf '%s\n' "$old" > "$TEST_IMAGES"
export REGISTRY_IMAGES="$registry" MOCK_IMAGE_ID="$first"
bash "$root/scan.sh"
jq -e --arg old "$old" --arg first "$first" '
  .images[0].source.reference == $old and
  .images[0].sbom == (($old | sub(":"; "-")) + ".spdx.json") and
  all(.images[]; .image_id == $first)
' "$(artifact_directory)/index.json" > /dev/null

prepare
export REGISTRY_IMAGES="$registry" REGISTRY_PLATFORM=linux/arm64/v8
bash "$root/scan.sh"
jq -e '.images | length == 1 and .[0].source.requested_platform == "linux/arm64/v8"' \
  "$(artifact_directory)/index.json" > /dev/null
grep -qx "registry:$registry" "$TEST_SCANS"

prepare
printf '%s\n' "$old" > "$TEST_IMAGES"
bash "$root/scan.sh"
grep -qx "docker:$old" "$TEST_SCANS"
test "$(wc -l < "$TEST_SCANS")" -eq 1

prepare
bash "$root/scan.sh" > "$root/no-images.log"
jq -e '.images == []' "$(artifact_directory)/index.json" > /dev/null
test ! -s "$TEST_SCANS"
grep -q '::notice::No local images or registry references found' "$root/no-images.log"

for failure in docker registry invalid-json invalid-metadata; do
  prepare
  printf '%s\n' "$old" "$second" > "$TEST_IMAGES"
  export REGISTRY_IMAGES="$registry"
  case "$failure" in
    docker) export FAIL_SYFT="docker:$old" ;;
    registry) export FAIL_SYFT="registry:$registry" ;;
    invalid-json) export MOCK_SBOM='{}' ;;
    invalid-metadata) export INVALID_METADATA=true ;;
  esac
  if bash "$root/scan.sh" > "$root/failure.log" 2>&1; then
    echo "Expected failure for $failure" >&2
    exit 1
  fi
  destination=$(artifact_directory)
  jq -e '.images | length == 3 and any(.[]; .status == "failed")' "$destination/index.json" > /dev/null
  count=$(jq '[.images[] | select(.status == "success")] | length' "$destination/index.json")
  test "$(find "$destination" -name '*.spdx.json' | wc -l)" -eq "$count"
  test "$(wc -l < "$TEST_SCANS")" -eq 3
  grep -q '::error::SBOM generation failed' "$root/failure.log"
  if [[ "$failure" == docker || "$failure" == registry ]]; then
    test "$count" -eq 2
  else
    test "$count" -eq 0
  fi
done

prepare
export REGISTRY_IMAGES="$registry"
export MOCK_SBOM='{"spdxVersion":"SPDX-2.3","packages":[]}'
bash "$root/scan.sh"
jq -e '.images[0].packages == 0' "$(artifact_directory)/index.json" > /dev/null

for failure in local-id registry-tag registry-url registry-missing-digest platform list; do
  prepare
  case "$failure" in
    local-id) printf '%s\n' invalid > "$TEST_IMAGES" ;;
    registry-tag) export REGISTRY_IMAGES=registry.example/test:latest ;;
    registry-url) export REGISTRY_IMAGES="https://$registry" ;;
    registry-missing-digest) export REGISTRY_IMAGES=registry.example/test@ ;;
    platform) export REGISTRY_PLATFORM=invalid ;;
    list) export FAIL_LIST=1 ;;
  esac
  if bash "$root/scan.sh" > /dev/null 2>&1; then
    echo "Expected validation failure for $failure" >&2
    exit 1
  fi
  test ! -s "$GITHUB_OUTPUT"
  test ! -s "$TEST_SCANS"
done
echo "PASS: local and registry sources, deduplication, platforms, metadata, checksums, and partial failures without Docker pulls."
