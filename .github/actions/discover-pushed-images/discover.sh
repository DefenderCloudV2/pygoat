#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

die() {
  echo "::error::$1" >&2
  exit 1
}

case "${DISCOVERY_PHASE:-}" in
  start)
    state=$(mktemp -d "$RUNNER_TEMP/pushed-image-discovery.XXXXXX")
    daemon=$(docker info --format '{{.ID}}')
    [[ -n "$daemon" ]] || die "Docker did not return a daemon ID."
    jq -n --arg daemon "$daemon" --arg started_at "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" '
      {schema_version: 1, started_at: $started_at, daemon_id: $daemon,
        repository: env.GITHUB_REPOSITORY, run_id: env.GITHUB_RUN_ID,
        run_attempt: env.GITHUB_RUN_ATTEMPT, job: env.GITHUB_JOB}
    ' > "$state/context.json"
    nohup bash "$GITHUB_ACTION_PATH/capture.sh" "$state" \
      > "$state/collector.log" 2>&1 < /dev/null &
    for ((attempt=0; attempt<50; attempt++)); do
      if [[ -f "$state/collector.exit" ]]; then
        cat "$state/collector.log" "$state/events.stderr" >&2
        die "Docker push-event capture failed to start."
      fi
      if [[ -f "$state/ready" ]]; then
        echo "state-directory=$state" >> "$GITHUB_OUTPUT"
        echo "Capturing Docker push events for this job."
        exit 0
      fi
      sleep 0.2
    done
    touch "$state/stop"
    die "Timed out starting Docker push-event capture."
    ;;
  collect) ;;
  *) die "phase must be start or collect." ;;
esac

state="${DISCOVERY_STATE:-}"
[[ -d "$state" && -f "$state/context.json" ]] || die "A valid state-directory from the start step is required."
jq -e '
  .schema_version == 1 and .repository == env.GITHUB_REPOSITORY and
  .run_id == env.GITHUB_RUN_ID and .run_attempt == env.GITHUB_RUN_ATTEMPT and .job == env.GITHUB_JOB
' "$state/context.json" > /dev/null || die "Discovery state belongs to a different job."
[[ ! -f "$state/stop" ]] || die "This discovery state has already been collected."
touch "$state/stop"
for ((attempt=0; attempt<100; attempt++)); do
  [[ -f "$state/collector.exit" ]] && break
  sleep 0.2
done

records="$state/records.jsonl"
errors="$state/errors.jsonl"
warnings="$state/warnings.jsonl"
: > "$records"
: > "$errors"
: > "$warnings"
error() {
  echo "::error::$1" >&2
  jq -nc --arg error "$1" '$error' >> "$errors"
}
if [[ ! -f "$state/collector.exit" ]] || [[ "$(cat "$state/collector.exit")" != 0 ]]; then
  error "Docker event capture was interrupted or did not stop cleanly; discovery may be incomplete."
fi
if daemon=$(docker info --format '{{.ID}}'); then
  expected=$(jq -r '.daemon_id' "$state/context.json" | tr -d '\r')
  [[ "$daemon" == "$expected" ]] || error "Docker daemon changed between start and collect."
else
  error "Cannot verify the Docker daemon at collection time."
fi

# Docker Hub shorthand is normalized, but tags are never substituted for digests.
repository_name() {
  local ref="$1" name first
  [[ "$ref" =~ ^[a-z0-9][A-Za-z0-9._:/@-]*$ && "$ref" != sha256:* ]] || return 1
  name="${ref%%@*}"
  if [[ "${name##*/}" == *:* ]]; then name="${name%:*}"; fi
  if [[ "$name" != */* ]]; then
    name="docker.io/library/$name"
  else
    first="${name%%/*}"
    if [[ "$first" != *.* && "$first" != *:* && "$first" != localhost ]]; then
      name="docker.io/$name"
    fi
  fi
  name="${name/#index.docker.io\//docker.io/}"
  if [[ "$name" == docker.io/* && "${name#docker.io/}" != */* ]]; then
    name="docker.io/library/${name#docker.io/}"
  fi
  [[ "$name" =~ ^[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*$ ]] || return 1
  printf '%s\n' "$name"
}

resolve_digest() {
  local ref="$1" digest
  digest=$(timeout 120 docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}') || return 1
  digest="${digest//$'\r'/}"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

if jq -sce '
  all(.[]; .type == "image" and .action == "push" and
    (.id | type == "string") and (.time | type == "number"))
' "$state/events.jsonl" > /dev/null; then
  jq -c '.' "$state/events.jsonl" | tr -d '\r' > "$state/events.normalized.jsonl"
  while IFS= read -r event; do
    ref=$(jq -r '.id' <<< "$event" | tr -d '\r')
    # Some daemon versions identify the actor by a content ID instead of a name.
    if [[ "$ref" == sha256:* || "$ref" =~ ^[0-9a-f]{64}$ ]]; then
      ref=$(jq -r '.name // ""' <<< "$event" | tr -d '\r')
    fi
    if [[ "$ref" != *@sha256:* && "${ref##*/}" != *:* ]]; then
      error "A Docker push event has no tagged or digested image reference; supply explicit build metadata."
      continue
    fi
    if ! repository=$(repository_name "$ref"); then
      error "A Docker push event contains an unsupported image reference."
      continue
    fi
    if ! digest=$(resolve_digest "$ref"); then
      error "Cannot resolve Docker push reference $ref to a registry digest."
      continue
    fi
    if [[ "$ref" == *@* && "${ref##*@}" != "$digest" ]]; then
      error "Registry digest mismatch for Docker push reference $ref."
      continue
    fi
    jq -nc --arg reference "$repository@$digest" --arg input "$ref" --argjson event "$event" '
      {reference: $reference, evidence: {kind: "docker-push-event", input: $input,
        time: $event.time, time_nano: $event.time_nano, digest_resolution: "registry-at-collection"}}
    ' >> "$records"
  done < "$state/events.normalized.jsonl"
  if [[ -s "$state/events.normalized.jsonl" ]]; then
    warning="Docker push events do not carry a guaranteed manifest digest; tag references are resolved at collection time. Use build/push digest outputs if a tag can be overwritten."
    echo "::warning::$warning"
    jq -nc --arg warning "$warning" '$warning' >> "$warnings"
  fi
else
  error "Docker push-event data is missing or malformed."
fi

metadata_records="$state/buildx.jsonl"
: > "$metadata_records"
parse_metadata() {
  jq -cs '
    if length == 1 then .[0] else error("Expected exactly one JSON document") end |
    (if type == "array" then . else [.] end) |
    if all(.[]; type == "object" and
      (.["image.name"] | type == "string" and length > 0) and
      (.["containerimage.digest"] | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
      (.["buildx.build.ref"] | . == null or type == "string"))
    then .[] | {names: .["image.name"], digest: .["containerimage.digest"], build_ref: .["buildx.build.ref"]}
    else error("Expected metadata from successful Buildx image pushes") end
  '
}
if [[ -n "${BUILDX_METADATA:-}" ]]; then
  if parse_metadata <<< "$BUILDX_METADATA" > "$state/metadata.parsed"; then
    cat "$state/metadata.parsed" >> "$metadata_records"
  else
    error "Invalid buildx-metadata input."
  fi
fi
printf '%s\n' "${BUILDX_METADATA_FILES:-}" | sed -e 's/\r$//' -e '/^[[:space:]]*$/d' > "$state/metadata-files.txt"
while IFS= read -r file; do
  if [[ -f "$file" ]] && parse_metadata < "$file" > "$state/metadata.parsed"; then
    cat "$state/metadata.parsed" >> "$metadata_records"
  else
    error "Cannot read valid Buildx metadata from $file."
  fi
done < "$state/metadata-files.txt"

tr -d '\r' < "$metadata_records" > "$state/buildx.normalized.jsonl"
while IFS= read -r metadata; do
  digest=$(jq -r '.digest' <<< "$metadata" | tr -d '\r')
  jq -r '.names | split(",")[] | gsub("^\\s+|\\s+$"; "")' <<< "$metadata" | tr -d '\r' > "$state/names.txt"
  while IFS= read -r name; do
    if ! repository=$(repository_name "$name"); then
      error "Buildx metadata contains an unsupported image name."
      continue
    fi
    if [[ "$name" == *@* && "${name##*@}" != "$digest" ]]; then
      error "Buildx image name has a digest inconsistent with its output metadata."
      continue
    fi
    jq -nc --arg reference "$repository@$digest" --arg name "$name" --argjson metadata "$metadata" '
      {reference: $reference, evidence: {kind: "buildx-metadata", input: $name, build_ref: $metadata.build_ref}}
    ' >> "$records"
  done < "$state/names.txt"
done < "$state/buildx.normalized.jsonl"

jq -s 'sort_by(.reference) | group_by(.reference) |
  map({reference: .[0].reference, evidence: (map(.evidence) | unique)})' "$records" > "$state/images.json"
while IFS= read -r reference; do
  expected="${reference##*@}"
  if ! actual=$(resolve_digest "$reference") || [[ "$actual" != "$expected" ]]; then
    error "Discovered image $reference could not be verified in the registry."
  fi
done < <(jq -r '.[].reference' "$state/images.json" | tr -d '\r')

jq --slurpfile images "$state/images.json" --slurpfile errors "$errors" --slurpfile warnings "$warnings" \
  --arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" '
  . + {finished_at: $finished_at, images: $images[0], errors: $errors, warnings: $warnings,
    status: (if ($errors | length) == 0 then "success" else "failed" end)}
' "$state/context.json" > "$state/discovery.json"
{
  echo "report-path=$state/discovery.json"
  echo "registry-images<<DISCOVERED_IMAGES"
  jq -r '.images[].reference' "$state/discovery.json"
  echo "DISCOVERED_IMAGES"
} >> "$GITHUB_OUTPUT"
count=$(jq '.images | length' "$state/discovery.json" | tr -d '\r')
echo "Discovered $count unique registry image references."
if [[ "$count" == 0 ]]; then
  echo "::notice::No pushed images discovered. Buildx pushes require metadata inputs; cache-only builds are not published images."
fi
jq -e '.status == "success"' "$state/discovery.json" > /dev/null
