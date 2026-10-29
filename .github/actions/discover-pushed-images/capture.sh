#!/usr/bin/env bash
set -euo pipefail

state="$1"
child=""
finish() {
  result=$?
  trap - EXIT
  if [[ -n "$child" ]]; then
    kill "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  printf '%s\n' "$result" > "$state/collector.exit"
  exit "$result"
}
trap finish EXIT
trap 'exit 1' TERM INT

# Only retain event identity, never arbitrary image labels.
format='{"type":{{json .Type}},"action":{{json .Action}},"id":{{json .Actor.ID}},"name":{{json (index .Actor.Attributes "name")}},"time":{{.Time}},"time_nano":"{{.TimeNano}}"}'
timeout --kill-after=5 21600 docker events --since "$(jq -r '.started_at' "$state/context.json" | tr -d '\r')" \
  --filter type=image --filter event=push --format "$format" \
  > "$state/events.jsonl" 2> "$state/events.stderr" &
child=$!
sleep 0.2
if ! kill -0 "$child" 2>/dev/null; then
  echo "Docker event stream exited during startup." >&2
  exit 1
fi
touch "$state/ready"
while [[ ! -f "$state/stop" ]]; do
  if ! kill -0 "$child" 2>/dev/null; then
    echo "Docker event stream exited before collection." >&2
    exit 1
  fi
  sleep 0.2
done
# Detect an interrupted stream even if collection was requested simultaneously.
if ! kill -0 "$child" 2>/dev/null; then
  echo "Docker event stream is no longer running." >&2
  exit 1
fi
