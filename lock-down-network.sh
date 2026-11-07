#!/bin/bash
#
# lock-down-network.sh — remove the setup-phase egress network.
#
# Run from the HOST after tool installation and before any scenario. Leaves
# ops-console (and docker-sandbox, if present) attached only to the internal
# cymylau-net, so scenarios cannot reach the internet or the Docker host.
# Idempotent. Re-attach for more installs with:
#   docker network connect <project>_setup-net <container>
set -eu
cd "$(dirname "$0")"
COMPOSE="${COMPOSE:-docker compose -f compose.yml}"
[ -f compose.privileged.yml ] && [ -n "${WITH_PRIVILEGED:-}" ] && COMPOSE="$COMPOSE -f compose.privileged.yml"

NET="$($COMPOSE config --format json | python3 -c 'import json,sys; c=json.load(sys.stdin); print(c["networks"]["setup-net"]["name"])')"
for svc in ops-console docker-sandbox; do
    cid="$($COMPOSE ps -q "$svc" 2>/dev/null || true)"
    [ -n "$cid" ] || continue
    if docker inspect -f '{{json .NetworkSettings.Networks}}' "$cid" | grep -q "\"$NET\""; then
        docker network disconnect "$NET" "$cid"
        echo "[lock-down] disconnected $svc from $NET"
    else
        echo "[lock-down] $svc already isolated"
    fi
done
