#!/usr/bin/env bash
set -euo pipefail
export GITHUB_ACTION_PATH
GITHUB_ACTION_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root=$(mktemp -d)
cleanup() {
  for state in "$root/runner with spaces"/pushed-image-discovery.*; do
    [[ -d "$state" ]] || continue
    touch "$state/stop"
    for ((attempt=0; attempt<100; attempt++)); do
      [[ -f "$state/collector.exit" ]] && break
      sleep 0.1
    done
  done
  rm -r -- "$root"
}
trap cleanup EXIT
mkdir "$root/bin" "$root/runner with spaces"
export RUNNER_TEMP="$root/runner with spaces" PATH="$root/bin:$PATH"
export GITHUB_OUTPUT="$root/output" TEST_EVENTS="$root/events" TEST_DIGESTS="$root/digests"
export TEST_COMMANDS="$root/commands" TEST_STREAM_STOPPED="$root/stream-stopped"
export GITHUB_REPOSITORY=example/repo GITHUB_RUN_ID=456 GITHUB_RUN_ATTEMPT=2 GITHUB_JOB=build
digest="sha256:$(printf '%064d' 1)"
second="sha256:$(printf '%064d' 2)"
export TEST_DIGEST="$digest"

cat > "$root/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_COMMANDS"
case "$1" in
  info)
    test "${FAIL_INFO:-0}" = 0
    printf '%s\n' "${TEST_DAEMON:-daemon-one}" ;;
  events)
    test "$2" = --since
    test "$4 $5 $6 $7" = "--filter type=image --filter event=push"
    test "$8" = --format
    [[ "$9" == *'.Actor.ID'* && "$9" != '{{json .}}' ]]
    test "${FAIL_STREAM:-0}" != startup
    trap 'touch "$TEST_STREAM_STOPPED"; exit 0' TERM INT
    cat "$TEST_EVENTS"
    if [[ "${FAIL_STREAM:-0}" == later ]]; then sleep 0.4; exit 1; fi
    while true; do sleep 0.1; done ;;
  buildx)
    test "$2 $3" = "imagetools inspect"
    test "$5 $6" = '--format {{.Manifest.Digest}}'
    test "${FAIL_REGISTRY:-0}" = 0
    jq -er --arg ref "$4" '.[$ref] // empty' "$TEST_DIGESTS" ;;
  *) echo "Unexpected Docker command: $*" >&2; exit 90 ;;
esac
MOCK
chmod +x "$root/bin/docker"

prepare() {
  unset FAIL_STREAM FAIL_REGISTRY FAIL_INFO TEST_DAEMON
  export BUILDX_METADATA="" BUILDX_METADATA_FILES=""
  : > "$TEST_EVENTS"
  : > "$TEST_COMMANDS"
  : > "$GITHUB_OUTPUT"
  rm -f "$TEST_STREAM_STOPPED"
  jq -n --arg digest "$digest" --arg second "$second" '{
    "registry.example/app:latest": $digest,
    ("registry.example/app@" + $digest): $digest,
    ("mirror.example/app@" + $digest): $digest,
    ("docker.io/library/alpine@" + $second): $second,
    ("localhost:5000/app@" + $second): $second,
    ("docker.io/team/app@" + $second): $second
  }' > "$TEST_DIGESTS"
}
start() {
  DISCOVERY_PHASE=start bash "$GITHUB_ACTION_PATH/discover.sh" > "$root/start.log" 2>&1
  DISCOVERY_STATE=$(sed -n 's/^state-directory=//p' "$GITHUB_OUTPUT")
  export DISCOVERY_STATE
  test -f "$DISCOVERY_STATE/ready"
  : > "$GITHUB_OUTPUT"
}
collect() {
  DISCOVERY_PHASE=collect bash "$GITHUB_ACTION_PATH/discover.sh" > "$root/collect.log" 2>&1
}
report() {
  printf '%s\n' "$DISCOVERY_STATE/discovery.json"
}

prepare
printf '%s\n' '{"type":"image","action":"push","id":"registry.example/app:latest","name":"registry.example/app","time":123,"time_nano":"123000000001"}' \
  > "$TEST_EVENTS"
cat "$TEST_EVENTS" >> "$root/duplicate"
cat "$root/duplicate" >> "$TEST_EVENTS"
BUILDX_METADATA=$(jq -nc --arg digest "$digest" '{
  "image.name": "registry.example/app:latest,registry.example/app:sha,mirror.example/app:latest,mirror.example/app:sha",
  "containerimage.digest": $digest, "buildx.build.ref": "builder/node/build-id",
  "buildx.build.provenance": {"private": "must-not-be-copied"}
}')
export BUILDX_METADATA
start
collect
test -f "$TEST_STREAM_STOPPED"
jq -e --arg digest "$digest" '
  .status == "success" and .errors == [] and (.warnings | length) == 1 and (.images | length) == 2 and
  any(.images[]; .reference == ("registry.example/app@" + $digest) and (.evidence | length) == 3) and
  any(.images[]; .reference == ("mirror.example/app@" + $digest) and (.evidence | length) == 2)
' "$(report)" > /dev/null
! grep -q 'must-not-be-copied' "$(report)"
test "$(grep -c '^registry-images<<' "$GITHUB_OUTPUT")" -eq 1
if collect; then echo "Repeated collection should fail" >&2; exit 1; fi

prepare
# Buildx-only pushes: no Docker events or local images are required.
BUILDX_METADATA=$(jq -nc --arg digest "$second" '[
  {"image.name":"alpine:ci,docker.io/alpine:ci,index.docker.io/alpine:ci,index.docker.io/team/app:ci","containerimage.digest":$digest},
  {"image.name":"localhost:5000/app:ci","containerimage.digest":$digest}
]')
export BUILDX_METADATA
start
collect
jq -e '.images | length == 3 and all(.[]; all(.evidence[]; .kind == "buildx-metadata"))' "$(report)" > /dev/null
! grep -q 'image ls\|image inspect\|history\|pull' "$TEST_COMMANDS"

prepare
printf '{"type":"image","action":"push","id":"%s","name":"registry.example/app:latest","time":123}\n' "$second" > "$TEST_EVENTS"
start
collect
jq -e --arg digest "$digest" '.images | length == 1 and .[0].reference == ("registry.example/app@" + $digest)' "$(report)" > /dev/null

prepare
export BUILDX_METADATA_FILES="$root/build metadata.json"
jq -n --arg digest "$digest" '{"image.name":"registry.example/app:ci","containerimage.digest":$digest}' > "$BUILDX_METADATA_FILES"
start
collect
jq -e '.images | length == 1' "$(report)" > /dev/null

prepare
export BUILDX_METADATA='[]'
start
collect
jq -e '.status == "success" and .images == [] and .warnings == []' "$(report)" > /dev/null
grep -q '::notice::No pushed images discovered' "$root/collect.log"

for failure in malformed empty-object multiple-documents bad-digest mismatched-digest missing-file ambiguous-event invalid-event registry registry-digest stream daemon; do
  prepare
  BUILDX_METADATA=$(jq -nc --arg digest "$digest" '{"image.name":"registry.example/app:ci","containerimage.digest":$digest}')
  export BUILDX_METADATA
  case "$failure" in
    malformed) export BUILDX_METADATA='{' ;;
    empty-object) export BUILDX_METADATA='{}' ;;
    multiple-documents) export BUILDX_METADATA="$BUILDX_METADATA"$'\n'"$BUILDX_METADATA" ;;
    bad-digest) export BUILDX_METADATA='{"image.name":"registry.example/app:ci","containerimage.digest":"sha256:bad"}' ;;
    mismatched-digest) BUILDX_METADATA=$(jq -nc --arg digest "$digest" --arg second "$second" '{"image.name":("registry.example/app@" + $second),"containerimage.digest":$digest}'); export BUILDX_METADATA ;;
    missing-file) export BUILDX_METADATA_FILES="$root/missing.json" ;;
    ambiguous-event) printf '{"type":"image","action":"push","id":"%s","name":"registry.example/app","time":123}\n' "$digest" > "$TEST_EVENTS" ;;
    invalid-event) printf 'not-json\n' > "$TEST_EVENTS" ;;
    registry) export FAIL_REGISTRY=1 ;;
    registry-digest) jq -n --arg digest "$digest" --arg second "$second" '{("registry.example/app@" + $digest): $second}' > "$TEST_DIGESTS" ;;
    stream) export FAIL_STREAM=later ;;
  esac
  start
  if [[ "$failure" == stream ]]; then sleep 1; fi
  if [[ "$failure" == daemon ]]; then export TEST_DAEMON=daemon-two; fi
  if collect; then echo "Expected discovery failure: $failure" >&2; exit 1; fi
  jq -e '.status == "failed" and (.errors | length) > 0' "$(report)" > /dev/null
  grep -q '^report-path=' "$GITHUB_OUTPUT"
done

prepare
start
export GITHUB_JOB=another-job
if collect; then echo "Cross-job state should fail" >&2; exit 1; fi
test ! -f "$DISCOVERY_STATE/stop"
export GITHUB_JOB=build
collect

prepare
export FAIL_STREAM=startup
if DISCOVERY_PHASE=start bash "$GITHUB_ACTION_PATH/discover.sh" > "$root/start.log" 2>&1; then
  echo "A failed event stream must fail startup" >&2
  exit 1
fi
grep -q '::error::Docker push-event capture failed to start' "$root/start.log"
echo "Pushed-image discovery tests passed."
