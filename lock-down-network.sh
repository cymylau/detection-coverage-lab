#!/bin/bash
#
# lock-down-network.sh — remove the setup-phase egress network, then prove it.
#
# Run from the HOST after tool installation and before any scenario.
#   1. Disconnects EVERY container attached to this project's setup-net
#      (ops-console and, with the privileged overlay, docker-sandbox), however
#      the lab was brought up and whichever compose files were used.
#   2. Checks that no running lab container still has a default route (read
#      from /proc/net/route, which every container has; no traffic is sent).
# Exits non-zero if egress remains, so nothing runs with internet access.
# Idempotent. Re-attach for more installs with:
#   docker network connect <project>_setup-net <container>
set -eu
cd "$(dirname "$0")"
# same project name rule as `docker compose` (and run-everything.sh)
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$PWD" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')}"

cname() { local n; n="$(docker inspect -f '{{.Name}}' "$1" 2>/dev/null)"; echo "${n#/}"; }

NETS="$(docker network ls -q --filter "label=com.docker.compose.project=${PROJECT}" \
                              --filter "label=com.docker.compose.network=setup-net")"
if [ -z "$NETS" ]; then
    echo "[lock-down] no setup-net network for project '${PROJECT}' (already removed, or the lab is not up)"
fi
for net in $NETS; do
    name="$(docker network inspect -f '{{.Name}}' "$net")"
    attached="$(docker network inspect -f '{{range $id, $c := .Containers}}{{$id}} {{end}}' "$net")"
    [ -n "$attached" ] || echo "[lock-down] nothing attached to $name"
    for cid in $attached; do
        docker network disconnect "$net" "$cid"
        echo "[lock-down] disconnected $(cname "$cid") from $name"
    done
done

# Verify: a container with no default route cannot reach anything outside the
# internal cymylau-net bridge (which has no gateway).
bad=0; n=0
for cid in $(docker ps -q --filter "label=com.docker.compose.project=${PROJECT}"); do
    n=$((n + 1))
    if docker exec "$cid" cat /proc/net/route 2>/dev/null | awk 'NR > 1 && $2 == "00000000" {f = 1} END {exit !f}'; then
        echo "[lock-down] !! $(cname "$cid") still has a default route (internet egress)" >&2
        bad=1
    fi
done
if [ "$bad" = 1 ]; then
    echo "[lock-down] !! egress NOT removed. Do not run scenarios; tear down with: bash run-everything.sh --down" >&2
    exit 1
fi
if [ "$n" = 0 ]; then
    echo "[lock-down] no running containers for project '${PROJECT}': nothing to check"
else
    echo "[lock-down] egress removed: none of the ${n} running lab container(s) has a default route"
fi
