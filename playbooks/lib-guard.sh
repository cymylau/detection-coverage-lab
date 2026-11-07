#!/bin/bash
# lib-guard.sh — source this from any playbook that modifies the executing
# environment (home dotfiles, crontab, shell history, ~/.ssh, ~/.aws).
# Refuses to continue unless running inside the lab's ops-console container,
# so a stray run on a real host cannot damage real data.
require_lab_container() {
    if [ "${LAB_CONTAINER:-}" != "1" ]; then
        echo "[guard] refusing to run: LAB_CONTAINER=1 is not set." >&2
        echo "[guard] this script modifies ~/.ssh, ~/.aws, ~/.bashrc, crontab and/or history." >&2
        echo "[guard] run it only inside the ops-console container (compose.yml sets this)." >&2
        exit 99
    fi
}
