#!/usr/bin/env bash
# Container smoke test: build the image, run it in demo mode, drive the API.
set -euo pipefail
IMAGE=${IMAGE:-signalbox:smoke}
NAME=signalbox-smoke
PORT=${PORT:-18080}
PASS=smoke-password-1
JAR=$(mktemp)
cleanup() {
  status=$?
  if [ $status -ne 0 ]; then docker logs "$NAME" 2>&1 | tail -80 || true; fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -f "$JAR"
  exit $status
}
trap cleanup EXIT

[ -z "${SKIP_BUILD:-}" ] && docker build -t "$IMAGE" .
docker run -d --name "$NAME" -p "$PORT:8080" -e SIGNALBOX_AUTH_PASSWORD="$PASS" "$IMAGE" demo >/dev/null

for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && break
  sleep 1
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] || { echo "not healthy"; exit 1; }

B=http://127.0.0.1:$PORT
curl -fsS "$B/health" | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"]=="ok"'
test "$(curl -s -o /dev/null -w '%{http_code}' "$B/api/devices")" = 401
test "$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"password":"wrong"}' "$B/api/login")" = 401
curl -fsS -c "$JAR" -H 'Content-Type: application/json' -d "{\"password\":\"$PASS\"}" "$B/api/login" >/dev/null
curl -fsS -b "$JAR" "$B/api/devices" | python3 -c 'import json,sys; assert len(json.load(sys.stdin))==3'
curl -fsS -b "$JAR" -X POST "$B/api/devices/gateway/test" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["status"]=="ok", d'
for _ in $(seq 1 30); do
  n=$(curl -fsS -b "$JAR" "$B/api/findings" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
  [ "$n" -gt 0 ] && break
  sleep 1
done
[ "$n" -gt 0 ] || { echo "no findings"; exit 1; }
[ "$(docker exec "$NAME" id -u)" != 0 ] || { echo "runs as root"; exit 1; }
docker exec "$NAME" sh -c 'test -f /data/signalbox.yaml && test -f /data/secret.key'
[ "$(docker exec "$NAME" stat -c %a /data/secret.key)" = 600 ] || { echo "secret.key not 0600"; exit 1; }
echo "smoke test passed"
