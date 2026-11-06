#!/bin/bash
#
# run-privileged-container-abuse.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates a container that holds extra Linux capabilities (SYS_PTRACE here,
# added by compose.privileged.yml) attempting host-namespace escape
# primitives. ops-console is never given `pid: host` or the real host
# namespaces, so these attempts are expected to fail against THIS
# container's own init (pid 1) rather than the real host's — the point is
# to generate the attempted syscalls/commands an EDR should flag regardless
# of whether the attempt succeeds.
#
#   capability discovery         Discovery (T1082-adjacent, capsh/getpcaps)
#   nsenter into pid 1            Escape to Host attempt            (T1611)
#   cgroup release_agent probe    Escape to Host via cgroups         (T1611)
# ---------------------------------------------------------------------------
set -u

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/privabuse_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Northline :: privileged-container-capability-abuse emulation :: session=$SESSION"

step "capability discovery (ATT&CK T1082-adjacent)"
if command -v capsh >/dev/null 2>&1; then
    capsh --print 2>&1 | tee -a "$LOG"
else
    grep -i cap /proc/self/status 2>&1 | tee -a "$LOG"
fi

step "attempt: nsenter into pid 1's namespaces (ATT&CK T1611)"
if command -v nsenter >/dev/null 2>&1; then
    nsenter --target 1 --mount --uts --ipc --net --pid -- id 2>&1 | tee -a "$LOG" \
        || say "(failed as expected — no real host pid namespace is shared into this container)"
else
    say "!! nsenter not installed — run: bash playbooks/install-container-tools.sh"
fi

step "probe: cgroup release_agent breakout surface (ATT&CK T1611, discovery only)"
# This is read-only discovery — it deliberately does NOT write to
# release_agent or trigger notify_on_release. On a vulnerable cgroup-v1 host
# configuration, actually doing so can be a genuinely working host escape,
# not just a detection-telemetry demo, so this script only checks and
# reports the writability of the surface rather than exercising it.
CGROOT="/sys/fs/cgroup"
if [ -d "$CGROOT" ]; then
    find "$CGROOT" -maxdepth 2 -iname 'release_agent' 2>/dev/null | tee -a "$LOG"
    RA="$(find "$CGROOT" -maxdepth 2 -iname 'release_agent' 2>/dev/null | head -n1)"
    if [ -n "${RA:-}" ] && [ -w "$RA" ]; then
        say "!! release_agent at $RA is WRITABLE from inside this container — that is itself" \
            " the finding: a host with this exposed is escapable via the well-known" \
            " release_agent technique. Not exercising it further (would risk a real" \
            " host escape rather than a detection demo)."
    else
        say "release_agent not found or not writable — expected in a non-privileged/cgroup-v2 container"
    fi
else
    say "(no $CGROOT visible)"
fi

step "Done — privileged-container-abuse emulation complete."
say "artifacts: $LOG"
