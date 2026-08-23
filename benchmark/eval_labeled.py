#!/usr/bin/env python3
"""
Evaluate skillvet against an EXTERNAL labeled dataset (malware/ + benign/ dirs),
e.g. MalSkillBench. Real recall + real precision, authored by others.

Usage:
  python3 benchmark/eval_labeled.py --malware <dir> --benign <dir> [--limit N] [--procs 8]
"""
import argparse, json, os, sys, time
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "skills", "skillvet", "scripts")))
import scan_skill as S


def skill_dirs(root, limit=0):
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__", "node_modules")]
        if any(f.lower() == "skill.md" for f in fn):
            out.append(dp)
            if limit and len(out) >= limit:
                return out
    return out


def scan_path(d):
    try:
        findings, _, _ = S.scan_dir(d)
        S.check_frontmatter(d, findings)
        S.scan_yara(d, findings)
    except Exception:
        findings = []
    seen, dd = set(), []
    for f in findings:
        k = (f["rule"], f["file"], f["line"])
        if k not in seen:
            seen.add(k); dd.append(f)
    counts = S.summarize(dd)
    flagged = (counts["high"] + counts["critical"]) > 0
    detected = len(dd) > 0
    # attack-type tag from MalSkillBench dir naming: ...__PI_B10 / __CI_B4 / __MIXED_B5
    tag = "?"
    base = os.path.basename(d)
    if "__" in base:
        tag = base.split("__", 1)[1].split("_")[0]
    return flagged, detected, tag


def run(dirs, procs):
    with Pool(procs) as p:
        return p.map(scan_path, dirs, chunksize=8)


def pct(n, d):
    return f"{(100.0*n/d):.1f}%" if d else "—"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malware", required=True)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--out", default=os.path.join(HERE, "RESULTS_external.md"))
    a = ap.parse_args()

    t0 = time.time()
    mal = skill_dirs(a.malware, a.limit)
    ben = skill_dirs(a.benign, a.limit)
    print(f"scanning {len(mal)} malware + {len(ben)} benign with {a.procs} procs…", flush=True)

    mr = run(mal, a.procs)
    br = run(ben, a.procs)

    TP = sum(1 for f, d, t in mr if f)
    FN = len(mr) - TP
    det = sum(1 for f, d, t in mr if d)
    FP = sum(1 for f, d, t in br if f)
    TN = len(br) - FP
    prec = TP / (TP + FP) if (TP + FP) else 0
    rec = TP / (TP + FN) if (TP + FN) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    acc = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) else 0

    # recall by attack-type tag
    from collections import Counter, defaultdict
    tag_tot, tag_hit = Counter(), Counter()
    for f, d, t in mr:
        tag_tot[t] += 1
        if f:
            tag_hit[t] += 1

    dt = time.time() - t0
    L = []
    L.append("# skillvet — external labeled benchmark (MalSkillBench)\n")
    L.append(f"_Dataset authored by others. Scanned {len(mal)} malware + {len(ben)} benign "
             f"in {dt:.0f}s (procs={a.procs}). Flagged = ≥1 high/critical finding._\n")
    L.append("| Metric | Value |")
    L.append("|--------|-------|")
    L.append(f"| Detection recall (any finding on malware) | **{pct(det, len(mr))}** ({det}/{len(mr)}) |")
    L.append(f"| Block recall (high/critical on malware) | **{pct(TP, len(mr))}** ({TP}/{len(mr)}) |")
    L.append(f"| Precision | **{pct(TP, TP+FP)}** ({TP}/{TP+FP}) |")
    L.append(f"| Benign false-positive rate | **{pct(FP, len(br))}** ({FP}/{len(br)}) |")
    L.append(f"| F1 | **{f1:.3f}** |")
    L.append(f"| Accuracy | **{pct(TP+TN, TP+TN+FP+FN)}** |")
    L.append("")
    L.append("## Block recall by attack-type tag\n")
    L.append("| Tag | Recall | Count |")
    L.append("|-----|--------|-------|")
    for t in sorted(tag_tot, key=lambda x: -tag_tot[x]):
        L.append(f"| {t} | {pct(tag_hit[t], tag_tot[t])} | {tag_hit[t]}/{tag_tot[t]} |")
    report = "\n".join(L)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print(f"\n[written to {a.out}]")


if __name__ == "__main__":
    main()
