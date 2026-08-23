#!/usr/bin/env python3
"""
SessionStart hook for skillvet.

Scans every installed skill directory (personal + project) with scan_skill.py
and, if any skill has high- or critical-severity findings, injects a concise
warning into the session so the user sees it before relying on those skills.

Claude Code has no "skill installed" event, so this runs at the start of every
session: a skill you added since last session gets scanned on next start.

The hook is intentionally conservative:
  * It never blocks the session and never errors out of it (any failure -> silent exit 0).
  * It only surfaces skills with high/critical findings, to avoid noise.
  * It reads its own location via CLAUDE_PLUGIN_ROOT and finds scan_skill.py in
    the bundled skill.
"""
import json
import os
import subprocess
import sys

MAX_SKILLS_REPORTED = 20


def find_scanner(plugin_root):
    # scan_skill.py lives in the bundled skill.
    candidates = [
        os.path.join(plugin_root, "skills", "skillvet", "scripts", "scan_skill.py"),
        os.path.join(plugin_root, "scripts", "scan_skill.py"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def skill_dirs():
    dirs = []
    home = os.path.expanduser("~")
    roots = [
        os.path.join(home, ".claude", "skills"),
        os.path.join(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd()), ".claude", "skills"),
    ]
    for root in roots:
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            p = os.path.join(root, name)
            # skip our own scanner, the synced cache bucket, and non-skill dirs
            if name in ("skillvet", "synced") or name.startswith("."):
                continue
            if os.path.isdir(p) and (
                os.path.isfile(os.path.join(p, "SKILL.md"))
                or os.path.isfile(os.path.join(p, "skill.md"))
            ):
                dirs.append(p)
    return dirs


def scan_counts(scanner, path):
    """Return (counts, verdict) or None on failure."""
    tmp = None
    try:
        import tempfile
        fd, tmp = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        subprocess.run(
            [sys.executable, scanner, path, "--json", tmp, "--quiet", "--fail-on", "critical"],
            capture_output=True, text=True, timeout=25,
        )
        with open(tmp, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("counts", {}), data.get("verdict", "")
    except Exception:
        return None
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def main():
    # Consume hook stdin (SessionStart payload) but we don't need it.
    try:
        sys.stdin.read()
    except Exception:
        pass

    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    scanner = find_scanner(plugin_root)
    if not scanner:
        sys.exit(0)

    risky = []
    for path in skill_dirs():
        result = scan_counts(scanner, path)
        if not result:
            continue
        counts, verdict = result
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        if crit or high:
            risky.append((os.path.basename(path), crit, high))
        if len(risky) >= MAX_SKILLS_REPORTED:
            break

    if not risky:
        sys.exit(0)

    lines = ["⚠️ skillvet flagged installed skills with high/critical security findings:"]
    for name, crit, high in sorted(risky, key=lambda x: (-x[1], -x[2])):
        lines.append(f"  • {name}: {crit} critical, {high} high")
    lines.append("")
    lines.append("Run `/skillvet <path-to-skill>` for a full report before trusting these. "
                 "A finding is a reason to review, not proof of malice.")
    context = "\n".join(lines)

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    }))
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never break the user's session.
        sys.exit(0)
