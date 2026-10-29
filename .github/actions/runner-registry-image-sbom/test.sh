#!/usr/bin/env bash
set -euo pipefail

action="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/action.yml"
root=$(mktemp -d)
trap 'rm -r -- "$root"' EXIT
mkdir "$root/bin" "$root/runner with spaces"
export RUNNER_TEMP="$root/runner with spaces"
export PATH="$root/bin:$PATH"
export TEST_IMAGES="$root/images" TEST_SCANS="$root/scans"
export TEST_INSPECT="$root/inspect.json"
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
case "$1 $2" in
  "image ls")
    test "$*" = "image ls --all --quiet --no-trunc"
    test "${FAIL_LIST:-0}" = 0
    cat "$TEST_IMAGES" ;;
  "image inspect")
    test -n "${EXCLUDE_IMAGES:-}"
    test "${FAIL_INSPECT:-}" != "$3"
    jq -ce --arg image "$3" '.[$image] | select(. != null)' "$TEST_INSPECT" ;;
  *) echo "Unexpected Docker command" >&2; exit 90 ;;
esac
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
printf '%s\n' "$MOCK_CYCLONEDX" > "${4#cyclonedx-json=}"
test "$5" = --output
jq -n --arg image "$image" --arg untagged "$UNTAGGED_IMAGE" \
  --argjson invalid "${INVALID_METADATA:-false}" '{
    source: {type: "image", metadata: {
      imageID: (if $invalid then "invalid" else $image end),
      tags: (if $image == $untagged then [] else ["example:ci", "example:alias"] end),
      repoDigests: [], manifestDigest: $image, os: "linux", architecture: "amd64",
      config: ({created: "2026-01-01T00:00:00Z", config: {Env: ["SECRET=omit-me"]}} | tojson | @base64),
      labels: {"org.opencontainers.image.revision": "commit", "private-label": "omit-me"}
    }}
  }' > "${6#syft-json=}"
test "$source" != "${FAIL_SYFT:-}"
MOCK
chmod +x "$root/bin/docker" "$root/bin/syft"
export SYFT_COMMAND="$root/bin/syft"

prepare() {
  unset FAIL_SYFT FAIL_LIST INVALID_METADATA MOCK_IMAGE_ID FAIL_INSPECT
  export REGISTRY_IMAGES="" REGISTRY_PLATFORM=linux/amd64 EXCLUDE_IMAGES=""
  export SCAN_LOCAL_IMAGES=true DISCOVERY_REPORT=""
  export MOCK_SBOM='{"spdxVersion":"SPDX-2.3","packages":[{"name":"fixture"}]}'
  export MOCK_CYCLONEDX='{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"fixture"}]}'
  : > "$TEST_IMAGES"
  : > "$GITHUB_OUTPUT"
  : > "$TEST_SCANS"
  printf '{}\n' > "$TEST_INSPECT"
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
    .cyclonedx.components == 1 and .cyclonedx.spec_version == "1.6" and
    .platform.architecture == "amd64" and .image_created_at == "2026-01-01T00:00:00Z" and
    .oci_labels == {"org.opencontainers.image.revision": "commit"}) and
  ([.images[].sbom] | unique | length) == 5
' "$index" > /dev/null
! grep -qE 'must-not-be-copied|omit-me' "$index"
test "$(find "$destination" -type f | wc -l)" -eq 11
while IFS= read -r filename; do
  file="$destination/$filename"
  jq -e --arg filename "$filename" --arg hash "$(sha256sum "$file" | cut -d ' ' -f 1)" \
    --argjson size "$(wc -c < "$file")" \
    'any(.images[]; .sbom == $filename and .sbom_sha256 == $hash and .sbom_size_bytes == $size)' "$index" > /dev/null
done < <(jq -r '.images[].sbom' "$index" | tr -d '\r')
while IFS= read -r filename; do
  file="$destination/$filename"
  jq -e --arg filename "$filename" --arg hash "$(sha256sum "$file" | cut -d ' ' -f 1)" \
    --argjson size "$(wc -c < "$file")" '
      any(.images[]; .cyclonedx.file == $filename and
        .cyclonedx.sha256 == $hash and .cyclonedx.size_bytes == $size)
    ' "$index" > /dev/null
done < <(jq -r '.images[].cyclonedx.file' "$index" | tr -d '\r')

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
export REGISTRY_IMAGES="$registry" SCAN_LOCAL_IMAGES=false FAIL_LIST=1
export DISCOVERY_REPORT="$root/discovery.json"
jq -n --arg reference "$registry" '{
  schema_version: 1, repository: env.GITHUB_REPOSITORY, run_id: env.GITHUB_RUN_ID,
  run_attempt: env.GITHUB_RUN_ATTEMPT, job: env.GITHUB_JOB,
  status: "success", images: [{reference: $reference, evidence: [{kind: "buildx-metadata"}]}],
  errors: [], warnings: []
}' > "$DISCOVERY_REPORT"
bash "$root/scan.sh"
destination=$(artifact_directory)
cmp "$DISCOVERY_REPORT" "$destination/discovery.json"
jq -e '.images | length == 1 and .[0].source.type == "registry"' "$destination/index.json" > /dev/null
test "$(wc -l < "$TEST_SCANS")" -eq 1
jq '.status = "failed" | .errors = ["Incomplete discovery"]' "$DISCOVERY_REPORT" > "$root/failed-discovery.json"
export DISCOVERY_REPORT="$root/failed-discovery.json"
: > "$GITHUB_OUTPUT"
if bash "$root/scan.sh" > "$root/incomplete.log" 2>&1; then
  echo "An incomplete discovery report must fail the scan after retaining results" >&2
  exit 1
fi
jq -e '.images[0].status == "success"' "$(artifact_directory)/index.json" > /dev/null
test -f "$(artifact_directory)/discovery.json"

for failure in invalid-local-option invalid-report wrong-job; do
  prepare
  case "$failure" in
    invalid-local-option) export SCAN_LOCAL_IMAGES=maybe ;;
    invalid-report) export DISCOVERY_REPORT="$root/bad-report.json"; echo '{}' > "$DISCOVERY_REPORT" ;;
    wrong-job)
      export DISCOVERY_REPORT="$root/wrong-job.json"
      jq '.job = "other-job"' "$root/discovery.json" > "$DISCOVERY_REPORT" ;;
  esac
  if bash "$root/scan.sh" > "$root/invalid.log" 2>&1; then
    echo "Expected validation failure: $failure" >&2; exit 1
  fi
  test ! -s "$TEST_SCANS"
done

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

for failure in docker registry invalid-json invalid-cyclonedx invalid-components multiple-cyclonedx invalid-metadata; do
  prepare
  printf '%s\n' "$old" "$second" > "$TEST_IMAGES"
  export REGISTRY_IMAGES="$registry"
  case "$failure" in
    docker) export FAIL_SYFT="docker:$old" ;;
    registry) export FAIL_SYFT="registry:$registry" ;;
    invalid-json) export MOCK_SBOM='{}' ;;
    invalid-cyclonedx) export MOCK_CYCLONEDX='{}' ;;
    invalid-components) export MOCK_CYCLONEDX='{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":false}' ;;
    multiple-cyclonedx) export MOCK_CYCLONEDX="$MOCK_CYCLONEDX"$'\n'"$MOCK_CYCLONEDX" ;;
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
  test "$(find "$destination" -name '*.cdx.json' | wc -l)" -eq "$count"
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
export MOCK_CYCLONEDX='{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}'
bash "$root/scan.sh"
jq -e '.images[0].packages == 0 and .images[0].cyclonedx.components == 0' "$(artifact_directory)/index.json" > /dev/null

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
prepare
helper="sha256:$(printf '%064d' 3)"
dependabot="sha256:$(printf '%064d' 4)"
github_registry="ghcr.io/github/tool@$first"
export EXCLUDE_IMAGES=$' ghcr.io/github/** \r\n\nmoby/**\n'
export REGISTRY_IMAGES="$github_registry"$'\n'"$registry"
printf '%s\n' "$old" "$first" "$second" "$helper" "$dependabot" > "$TEST_IMAGES"
jq -n --arg old "$old" --arg first "$first" --arg second "$second" \
  --arg helper "$helper" --arg dependabot "$dependabot" '{
    ($old): [{RepoTags: ["docker.io/moby/buildkit:latest"], RepoDigests: []}],
    ($first): [{RepoTags: ["ghcr.io/github/tool:latest", "example:alias"], RepoDigests: []}],
    ($second): [{RepoTags: [], RepoDigests: []}],
    ($helper): [{RepoTags: [], RepoDigests: ["ghcr.io/github/helper@sha256:abc"]}],
    ($dependabot): [{RepoTags: ["ghcr.io/dependabot/dependabot-updater-core:latest"], RepoDigests: []}]
  }' > "$TEST_INSPECT"
bash "$root/scan.sh"
index="$(artifact_directory)/index.json"
test "$(wc -l < "$TEST_SCANS")" -eq 3
jq -e --arg old "$old" --arg first "$first" --arg second "$second" \
  --arg helper "$helper" --arg dependabot "$dependabot" --arg registry "$registry" '
  (.images | length) == 7 and
  ([.images[] | select(.status == "excluded")] | length) == 4 and
  all(.images[] | select(.status == "excluded");
    .exclusion.pattern != null and (has("sbom") | not) and (has("cyclonedx") | not)) and
  any(.images[]; .source.reference == $old and .exclusion.pattern == "moby/**") and
  any(.images[]; .source.reference == $first and .status == "excluded") and
  any(.images[]; .source.reference == $helper and .status == "excluded" and .tags == []) and
  all(.images[] | select(.source.reference == $second or .source.reference == $dependabot or .source.reference == $registry);
    .status == "success")
' "$index" > /dev/null
grep -qx "docker:$second" "$TEST_SCANS"
grep -qx "docker:$dependabot" "$TEST_SCANS"
grep -qx "registry:$registry" "$TEST_SCANS"
test "$(find "$(artifact_directory)" -name '*.spdx.json' | wc -l)" -eq 3
test "$(find "$(artifact_directory)" -name '*.cdx.json' | wc -l)" -eq 3

export EXCLUDE_IMAGES="${EXCLUDE_IMAGES}"$'\nghcr.io/dependabot/**'
: > "$GITHUB_OUTPUT"
: > "$TEST_SCANS"
bash "$root/scan.sh"
jq -e --arg dependabot "$dependabot" '
  ([.images[] | select(.status == "excluded")] | length) == 5 and
  any(.images[]; .source.reference == $dependabot and .status == "excluded" and
    .exclusion.pattern == "ghcr.io/dependabot/**")
' "$(artifact_directory)/index.json" > /dev/null
test "$(wc -l < "$TEST_SCANS")" -eq 2
! grep -qx "docker:$dependabot" "$TEST_SCANS"
grep -qx "docker:$second" "$TEST_SCANS"
grep -qx "registry:$registry" "$TEST_SCANS"
test "$(find "$(artifact_directory)" -name '*.spdx.json' | wc -l)" -eq 2
test "$(find "$(artifact_directory)" -name '*.cdx.json' | wc -l)" -eq 2

prepare
export EXCLUDE_IMAGES='ghcr.io/github/**' REGISTRY_IMAGES="$github_registry"
bash "$root/scan.sh"
test ! -s "$TEST_SCANS"
jq -e '.images | length == 1 and .[0].status == "excluded"' "$(artifact_directory)/index.json" > /dev/null
grep -q 'excluded 1 sources; generated 0 SPDX/CycloneDX SBOM pairs' "$GITHUB_STEP_SUMMARY"

for failure in inspect invalid-inspection; do
  prepare
  export EXCLUDE_IMAGES='moby/**' REGISTRY_IMAGES="$registry"
  printf '%s\n' "$old" > "$TEST_IMAGES"
  case "$failure" in
    inspect) export FAIL_INSPECT="$old" ;;
    invalid-inspection) jq -n --arg old "$old" '{($old): [{} , {}]}' > "$TEST_INSPECT" ;;
  esac
  if bash "$root/scan.sh" > "$root/failure.log" 2>&1; then
    echo "Expected exclusion inspection failure for $failure" >&2
    exit 1
  fi
  jq -e '.images[0].status == "failed" and .images[1].status == "success"' \
    "$(artifact_directory)/index.json" > /dev/null
  grep -q '::error::Cannot inspect' "$root/failure.log"
done
echo "PASS: local and registry sources, exclusions, SPDX/CycloneDX exports, checksums, and partial failures without Docker pulls."
