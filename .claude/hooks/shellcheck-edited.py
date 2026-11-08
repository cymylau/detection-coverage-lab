#!/usr/bin/env python3
"""PostToolUse hook (Edit|Write): ShellCheck a .sh file Claude just changed.

Runs the same ShellCheck image and level as CI. Warnings are fed back to Claude
(decision: block on PostToolUse only reports; the edit itself stands). Silent
when the file is not a shell script, is outside the repo, or is clean. If Docker
is unavailable it says so once and does not block.
"""
import json, os, subprocess, sys

IMAGE = "koalaman/shellcheck:v0.10.0"


def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return 0
    path = (data.get("tool_input") or {}).get("file_path") or (data.get("tool_response") or {}).get("filePath") or ""
    root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    if not path.endswith(".sh"):
        return 0
    path = os.path.realpath(path)
    root = os.path.realpath(root)
    if not path.startswith(root + os.sep) or not os.path.isfile(path):
        return 0
    rel = os.path.relpath(path, root)
    try:
        p = subprocess.run(["docker", "run", "--rm", "-v", f"{root}:/mnt", "-w", "/mnt", IMAGE, "-S", "warning", rel],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        print(json.dumps({"systemMessage": f"shellcheck hook skipped ({e.__class__.__name__}); run it before committing"}))
        return 0
    if p.returncode == 0:
        return 0
    out = (p.stdout + p.stderr).strip()
    if "Unable to find image" in out or "Cannot connect to the Docker daemon" in out:
        print(json.dumps({"systemMessage": "shellcheck hook skipped: Docker or the ShellCheck image is unavailable"}))
        return 0
    print(json.dumps({
        "decision": "block",
        "reason": f"ShellCheck (-S warning, as CI runs it) reports problems in {rel}. Fix them, or add an inline "
                  f"'# shellcheck disable=SCxxxx  # reason' if intentional:\n\n{out[:4000]}",
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
