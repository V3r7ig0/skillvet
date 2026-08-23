#!/usr/bin/env python3
"""
skillvet — watcher + quarantine daemon.

A real install-time gate for Agent Skills. It watches your skills directories,
and the moment a new (or changed) skill appears it runs the static scanner. If
the skill has findings at/above the quarantine threshold, it MOVES the skill
into a quarantine folder so Claude Code never loads it, writes a full report,
and notifies you. You then decide: `approve` moves it back into place, `reject`
deletes it.

This does not depend on an open Claude session and does not require any
third-party packages — just Python 3.8+ and scan_skill.py from this repo.

Commands
--------
  watch                 Run the daemon (foreground). Ctrl-C to stop.
  status                List quarantined skills and pending reports.
  approve <name>        Move a quarantined skill back into the skills dir.
  reject  <name>        Delete a quarantined skill permanently.
  report  <name>        Print the saved scan report for a quarantined skill.
  scan    <path>        One-off scan of a skill dir/archive (no quarantine).

Key options (watch)
-------------------
  --dir <path>          A skills directory to watch (repeatable). Default:
                        ~/.claude/skills and $CLAUDE_PROJECT_DIR/.claude/skills
  --interval <sec>      Poll interval. Default: 2.0
  --fail-on <sev>       Quarantine skills with a finding >= this severity.
                        (critical|high|medium|low). Default: high
  --scanner <path>      Path to scan_skill.py. Default: resolved from this file.
  --no-quarantine       Notify only; never move anything (dry run of the gate).

Layout it manages, inside each watched dir:
  .quarantine/<name>/            the moved skill
  .quarantine/<name>.report.md   its scan report
  .quarantine/ledger.json        record of what was quarantined and when
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
QUARANTINE_DIRNAME = ".quarantine"
SKIP_NAMES = {"skillvet", "synced", QUARANTINE_DIRNAME}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def default_scanner():
    here = os.path.dirname(os.path.abspath(__file__))
    cand = [
        os.path.join(here, "..", "skills", "skillvet", "scripts", "scan_skill.py"),
        os.path.join(here, "scan_skill.py"),
    ]
    for c in cand:
        c = os.path.normpath(c)
        if os.path.isfile(c):
            return c
    return None


def default_dirs():
    """Known skill directories across agents. Agent Skills (SKILL.md) is an open
    standard, so skillvet watches the common locations for Claude Code, Codex,
    and Cursor. Non-existent dirs are skipped by the watch loop; add your own
    with --dir."""
    home = os.path.expanduser("~")
    dirs = [
        os.path.join(home, ".claude", "skills"),   # Claude Code / Cowork
        os.path.join(home, ".codex", "skills"),    # Codex
        os.path.join(home, ".cursor", "skills"),   # Cursor
        os.path.join(home, ".config", "agent-skills"),  # generic
    ]
    proj = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    for sub in (".claude", ".codex", ".cursor"):
        dirs.append(os.path.join(proj, sub, "skills"))
    # de-dup, preserve order
    seen, out = set(), []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def is_skill_dir(path):
    return os.path.isdir(path) and (
        os.path.isfile(os.path.join(path, "SKILL.md"))
        or os.path.isfile(os.path.join(path, "skill.md"))
    )


def signature(path):
    """A cheap fingerprint of a skill dir: sorted (relpath, mtime, size)."""
    sig = []
    for dp, dn, fn in os.walk(path):
        dn[:] = [d for d in dn if d not in ("__pycache__", ".git")]
        for f in sorted(fn):
            ap = os.path.join(dp, f)
            try:
                st = os.stat(ap)
                sig.append((os.path.relpath(ap, path), int(st.st_mtime), st.st_size))
            except OSError:
                continue
    return tuple(sorted(sig))


def notify(title, message):
    """Best-effort desktop notification; falls back to stderr."""
    try:
        if sys.platform == "darwin":
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{message}" with title "{title}"'],
                capture_output=True, timeout=5)
            return
        if sys.platform.startswith("linux") and shutil.which("notify-send"):
            subprocess.run(["notify-send", title, message], capture_output=True, timeout=5)
            return
        if os.name == "nt":
            # Best-effort Windows balloon tip via PowerShell + WinForms (built in,
            # no install). Falls through to stderr if PowerShell is unavailable.
            safe_t = title.replace("'", "")
            safe_m = message.replace("'", "")
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms;"
                "$n=New-Object System.Windows.Forms.NotifyIcon;"
                "$n.Icon=[System.Drawing.SystemIcons]::Warning;"
                "$n.BalloonTipTitle='" + safe_t + "';"
                "$n.BalloonTipText='" + safe_m + "';"
                "$n.Visible=$true;$n.ShowBalloonTip(8000);Start-Sleep -s 9;$n.Dispose()"
            )
            subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=12)
            return
    except Exception:
        pass
    print(f"\n[!] {title}: {message}", file=sys.stderr, flush=True)


def run_scan(scanner, path, report_path=None):
    """Return (counts, verdict) and optionally write a markdown report."""
    import tempfile
    fd, tmp = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    args = [sys.executable, scanner, path, "--json", tmp, "--quiet", "--fail-on", "critical"]
    if report_path:
        args += ["--markdown", report_path]
    try:
        subprocess.run(args, capture_output=True, text=True, timeout=60)
        with open(tmp, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("counts", {}), data.get("verdict", "")
    except Exception as e:
        return None, f"scan error: {e}"
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def worst_severity(counts):
    for s in ("critical", "high", "medium", "low", "info"):
        if counts.get(s):
            return s
    return "info"


def ledger_path(watch_dir):
    return os.path.join(watch_dir, QUARANTINE_DIRNAME, "ledger.json")


def load_ledger(watch_dir):
    p = ledger_path(watch_dir)
    if os.path.isfile(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_ledger(watch_dir, data):
    qd = os.path.join(watch_dir, QUARANTINE_DIRNAME)
    os.makedirs(qd, exist_ok=True)
    with open(ledger_path(watch_dir), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Core actions
# --------------------------------------------------------------------------- #
def quarantine(watch_dir, name, counts, verdict, scanner):
    qd = os.path.join(watch_dir, QUARANTINE_DIRNAME)
    os.makedirs(qd, exist_ok=True)
    src = os.path.join(watch_dir, name)
    dst = os.path.join(qd, name)
    if os.path.exists(dst):
        shutil.rmtree(dst, ignore_errors=True)
    report = os.path.join(qd, f"{name}.report.md")
    # (Re)generate the full report from the source before moving.
    run_scan(scanner, src, report_path=report)
    shutil.move(src, dst)
    led = load_ledger(watch_dir)
    led[name] = dict(quarantined_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                     counts=counts, verdict=verdict, report=os.path.basename(report))
    save_ledger(watch_dir, led)
    return report


def approve(watch_dir, name):
    qd = os.path.join(watch_dir, QUARANTINE_DIRNAME)
    src = os.path.join(qd, name)
    dst = os.path.join(watch_dir, name)
    if not os.path.isdir(src):
        print(f"error: '{name}' is not in quarantine at {qd}", file=sys.stderr)
        return 2
    if os.path.exists(dst):
        print(f"error: '{dst}' already exists; remove it first", file=sys.stderr)
        return 2
    shutil.move(src, dst)
    report = os.path.join(qd, f"{name}.report.md")
    if os.path.exists(report):
        os.remove(report)
    led = load_ledger(watch_dir)
    led.pop(name, None)
    save_ledger(watch_dir, led)
    print(f"approved: '{name}' restored to {dst}")
    return 0


def reject(watch_dir, name):
    qd = os.path.join(watch_dir, QUARANTINE_DIRNAME)
    src = os.path.join(qd, name)
    if not os.path.isdir(src):
        print(f"error: '{name}' is not in quarantine at {qd}", file=sys.stderr)
        return 2
    shutil.rmtree(src, ignore_errors=True)
    report = os.path.join(qd, f"{name}.report.md")
    if os.path.exists(report):
        os.remove(report)
    led = load_ledger(watch_dir)
    led.pop(name, None)
    save_ledger(watch_dir, led)
    print(f"rejected: '{name}' deleted permanently")
    return 0


def status(watch_dirs):
    any_found = False
    for wd in watch_dirs:
        led = load_ledger(wd)
        if not led:
            continue
        any_found = True
        print(f"\nQuarantine in {os.path.join(wd, QUARANTINE_DIRNAME)}:")
        for name, info in led.items():
            c = info.get("counts", {})
            print(f"  • {name}  [{worst_severity(c)}]  "
                  f"crit={c.get('critical',0)} high={c.get('high',0)} "
                  f"med={c.get('medium',0)}  quarantined {info.get('quarantined_at','?')}")
        print(f"  approve:  skillvet_watch.py approve <name>")
        print(f"  reject:   skillvet_watch.py reject  <name>")
        print(f"  report:   skillvet_watch.py report  <name>")
    if not any_found:
        print("No skills are in quarantine.")
    return 0


def report_cmd(watch_dirs, name):
    for wd in watch_dirs:
        rp = os.path.join(wd, QUARANTINE_DIRNAME, f"{name}.report.md")
        if os.path.isfile(rp):
            with open(rp, "r", encoding="utf-8") as f:
                print(f.read())
            return 0
    print(f"error: no report found for '{name}'", file=sys.stderr)
    return 2


# --------------------------------------------------------------------------- #
# Watch loop
# --------------------------------------------------------------------------- #
def handle_skill(wd, name, args, scanner, threshold, known, first=False):
    """Scan one skill dir (wd/name) if it changed, and act (quarantine/warn)."""
    if name in SKIP_NAMES or name.startswith("."):
        return
    path = os.path.join(wd, name)
    if not is_skill_dir(path):
        return
    sig = signature(path)
    prev = known.setdefault(wd, {}).get(name)
    if sig == prev:
        return  # unchanged
    known[wd][name] = sig

    counts, verdict = run_scan(scanner, path)
    if counts is None:
        return
    worst = worst_severity(counts)
    sev_val = SEV[worst]
    tag = "new" if prev is None else "changed"

    if sev_val >= threshold:
        if args.no_quarantine:
            notify("skillvet", f"{name} ({tag}) is risky [{worst}] — quarantine disabled")
            print(f"[RISK] {name} ({tag}) worst={worst} "
                  f"crit={counts.get('critical',0)} high={counts.get('high',0)} "
                  f"— NOT quarantined (--no-quarantine)", flush=True)
        else:
            rp = quarantine(wd, name, counts, verdict, scanner)
            known[wd].pop(name, None)  # it moved out
            notify("skillvet — skill quarantined",
                   f"{name} had {counts.get('critical',0)} critical / "
                   f"{counts.get('high',0)} high findings. Review before approving.")
            print(f"[QUARANTINED] {name} ({tag}) worst={worst} -> {rp}", flush=True)
            print(f"   approve: {os.path.basename(__file__)} approve {name}", flush=True)
            print(f"   reject:  {os.path.basename(__file__)} reject {name}", flush=True)
    elif sev_val >= SEV["medium"]:
        notify("skillvet", f"{name} ({tag}) has {worst} findings — review recommended")
        print(f"[WARN] {name} ({tag}) worst={worst} — left in place", flush=True)
    elif first and prev is None:
        print(f"[ok] {name} — no significant findings", flush=True)


def _sweep_all(watch_dirs, args, scanner, threshold, known, first=False):
    """Scan every skill currently present across all watch dirs once."""
    for wd in watch_dirs:
        if not os.path.isdir(wd):
            continue
        try:
            entries = os.listdir(wd)
        except OSError:
            continue
        for name in entries:
            handle_skill(wd, name, args, scanner, threshold, known, first=first)


def _skill_name_for(wd, changed_path):
    """Given a changed path under wd, return the top-level skill folder name."""
    try:
        rel = os.path.relpath(changed_path, wd)
    except ValueError:
        return None
    if rel.startswith(".."):
        return None
    return rel.split(os.sep, 1)[0]


def watch(args, watch_dirs, scanner):
    threshold = SEV[args.fail_on]
    known = {wd: {} for wd in watch_dirs}

    # Try event-based watching (watchdog); fall back to polling.
    observer = None
    if not getattr(args, "poll", False):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except Exception:
            Observer = None
        if Observer is not None:
            observer = _start_event_watch(watch_dirs, args, scanner, threshold, known,
                                          Observer, FileSystemEventHandler)

    mode = "event-based (watchdog)" if observer else "polling"
    print(f"skillvet watcher started — {mode}. threshold=>={args.fail_on} "
          f"quarantine={'off' if args.no_quarantine else 'on'}", flush=True)
    for wd in watch_dirs:
        print(f"  watching {wd}", flush=True)

    # Initial sweep of already-installed skills (both modes).
    _sweep_all(watch_dirs, args, scanner, threshold, known, first=True)

    if observer:
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        while True:
            time.sleep(args.interval)
            _sweep_all(watch_dirs, args, scanner, threshold, known)


def _start_event_watch(watch_dirs, args, scanner, threshold, known, Observer, Handler):
    """Set up watchdog observers. Returns a started Observer, or None on failure."""
    last = {}  # (wd,name) -> last handled monotonic time (debounce)

    class _H(Handler):
        def __init__(self, wd):
            super().__init__()
            self.wd = wd

        def on_any_event(self, event):
            name = _skill_name_for(self.wd, event.src_path)
            if not name:
                return
            key = (self.wd, name)
            now = time.monotonic()
            if now - last.get(key, 0) < 1.0:  # debounce rapid bursts
                return
            last[key] = now
            # small settle delay so multi-file installs are seen whole
            time.sleep(0.4)
            try:
                handle_skill(self.wd, name, args, scanner, threshold, known)
            except Exception:
                pass

    try:
        obs = Observer()
        started = False
        for wd in watch_dirs:
            if os.path.isdir(wd):
                obs.schedule(_H(wd), wd, recursive=True)
                started = True
        if not started:
            # No dirs exist yet; watchdog can't watch a missing path. Fall back.
            return None
        obs.start()
        return obs
    except Exception:
        return None


# --------------------------------------------------------------------------- #
def main(argv):
    ap = argparse.ArgumentParser(description="skillvet watcher + quarantine daemon.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("watch", help="run the daemon")
    w.add_argument("--dir", action="append", dest="dirs")
    w.add_argument("--interval", type=float, default=2.0,
                   help="Polling interval in seconds (used only in polling fallback mode)")
    w.add_argument("--poll", action="store_true",
                   help="Force polling even if watchdog (event-based) is installed")
    w.add_argument("--fail-on", default="high", choices=[k for k in SEV if k != "info"])
    w.add_argument("--scanner")
    w.add_argument("--no-quarantine", action="store_true")

    for cname, helptext in (("status", "list quarantined skills"),
                            ("scan", "one-off scan (no quarantine)")):
        p = sub.add_parser(cname, help=helptext)
        p.add_argument("--dir", action="append", dest="dirs")
        if cname == "scan":
            p.add_argument("target")
            p.add_argument("--scanner")

    for cname in ("approve", "reject", "report"):
        p = sub.add_parser(cname)
        p.add_argument("name")
        p.add_argument("--dir", action="append", dest="dirs")

    args = ap.parse_args(argv)
    watch_dirs = args.dirs if getattr(args, "dirs", None) else default_dirs()

    if args.cmd == "scan":
        scanner = getattr(args, "scanner", None) or default_scanner()
        if not scanner:
            print("error: scan_skill.py not found; pass --scanner", file=sys.stderr)
            return 2
        import tempfile
        fd, rep = tempfile.mkstemp(suffix=".md")
        os.close(fd)
        counts, verdict = run_scan(scanner, args.target, report_path=rep)
        with open(rep, "r", encoding="utf-8") as f:
            print(f.read())
        os.remove(rep)
        return 0

    if args.cmd == "status":
        return status(watch_dirs)
    if args.cmd == "report":
        return report_cmd(watch_dirs, args.name)
    if args.cmd == "approve":
        return approve(watch_dirs[0], args.name)
    if args.cmd == "reject":
        return reject(watch_dirs[0], args.name)

    # watch
    scanner = args.scanner or default_scanner()
    if not scanner:
        print("error: scan_skill.py not found; pass --scanner", file=sys.stderr)
        return 2
    try:
        watch(args, watch_dirs, scanner)
    except KeyboardInterrupt:
        print("\nskillvet watcher stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
