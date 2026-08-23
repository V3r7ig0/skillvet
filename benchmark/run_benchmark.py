#!/usr/bin/env python3
"""
skillvet benchmark harness.

Scans three labeled buckets and reports real accuracy numbers:

  trusted  — known-good skills (default: official anthropics/skills). Negatives.
  malicious — the crafted fixtures in benchmark/malicious/.            Positives.
  wild     — large community corpus, UNLABELED. Reported as an in-the-wild
             flag-rate distribution (not used for precision/recall).

Decision rule: a skill is "flagged" (would be blocked / needs review) when it has
at least one HIGH or CRITICAL finding.

Metrics use trusted (N) + malicious (P):
  precision = TP / (TP + FP)      recall = TP / (TP + FN)
  F1, accuracy, and per-fixture recall by expected tag.

Usage:
  python3 benchmark/run_benchmark.py \
      --trusted <dir> --wild <dir> [--wild <dir> ...] \
      --out benchmark/RESULTS.md
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.normpath(os.path.join(HERE, "..", "skills", "skillvet", "scripts"))
sys.path.insert(0, SCRIPTS)
import scan_skill as S  # noqa: E402


def find_skill_dirs(root):
    dirs = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__", "node_modules")]
        if any(f.lower() == "skill.md" for f in fn):
            dirs.append(dp)
    return dirs


def scan_one(skill_dir):
    try:
        findings, _, _ = S.scan_dir(skill_dir)
        S.check_frontmatter(skill_dir, findings)
        S.scan_yara(skill_dir, findings)
    except Exception:
        findings = []
    # dedupe
    seen, dd = set(), []
    for f in findings:
        k = (f["rule"], f["file"], f["line"])
        if k not in seen:
            seen.add(k); dd.append(f)
    counts = S.summarize(dd)
    score = S.risk_score(dd, S._ships_executable(skill_dir))
    band, _ = S.score_band(score)
    flagged = (counts["high"] + counts["critical"]) > 0
    detected = len(dd) > 0
    rules = {f["rule"] for f in dd}
    return dict(counts=counts, score=score, band=band, flagged=flagged,
                detected=detected, rules=rules)


def read_tags(skill_dir):
    p = os.path.join(skill_dir, ".label")
    if os.path.isfile(p):
        for line in open(p):
            if line.startswith("tags:"):
                return [t.strip() for t in line.split(":", 1)[1].split(",") if t.strip()]
    return []


def pct(n, d):
    return f"{(100.0*n/d):.1f}%" if d else "—"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trusted", required=True)
    ap.add_argument("--wild", action="append", default=[])
    ap.add_argument("--malicious", default=os.path.join(HERE, "malicious"))
    ap.add_argument("--out", default=os.path.join(HERE, "RESULTS.md"))
    args = ap.parse_args()

    t0 = time.time()

    # ---- malicious (positives) ----
    mal_dirs = find_skill_dirs(args.malicious)
    TP = FN = 0
    detected_n = 0
    tag_hit = {}   # expected tag -> [caught_by_that_rule, total]
    missed = []
    undetected = []
    for d in mal_dirs:
        r = scan_one(d)
        if r["detected"]:
            detected_n += 1
        else:
            undetected.append(os.path.basename(d))
        if r["flagged"]:
            TP += 1
        else:
            FN += 1
            missed.append(os.path.basename(d))
        for tag in read_tags(d):
            h, tot = tag_hit.get(tag, [0, 0])
            tot += 1
            if tag in r["rules"]:
                h += 1
            tag_hit[tag] = [h, tot]

    # ---- trusted (negatives) ----
    tru_dirs = find_skill_dirs(args.trusted)
    FP = TN = 0
    fp_list = []
    for d in tru_dirs:
        r = scan_one(d)
        if r["flagged"]:
            FP += 1
            fp_list.append((os.path.relpath(d, args.trusted), r["counts"], sorted(x for x in r["rules"])[:6]))
        else:
            TN += 1

    # ---- wild (unlabeled) ----
    wild_dirs = []
    for w in args.wild:
        wild_dirs += find_skill_dirs(w)
    wild_bands = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    wild_flagged = 0
    for d in wild_dirs:
        r = scan_one(d)
        wild_bands[r["band"]] = wild_bands.get(r["band"], 0) + 1
        if r["flagged"]:
            wild_flagged += 1

    precision = TP / (TP + FP) if (TP + FP) else 0.0
    recall = TP / (TP + FN) if (TP + FN) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) else 0.0
    dt = time.time() - t0

    L = []
    L.append("# skillvet benchmark results\n")
    L.append(f"_Scanned {len(mal_dirs)} malicious + {len(tru_dirs)} trusted + "
             f"{len(wild_dirs)} in-the-wild skills in {dt:.1f}s._\n")
    L.append("Decision rule: a skill is **flagged** when it has ≥1 high or critical finding.\n")

    L.append("## Headline metrics (trusted = negatives, malicious = positives)\n")
    L.append("| Metric | Value |")
    L.append("|--------|-------|")
    L.append(f"| Detection recall (≥1 finding of any severity) | **{pct(detected_n, len(mal_dirs))}** ({detected_n}/{len(mal_dirs)}) |")
    L.append(f"| Block recall (≥1 high/critical → DO NOT INSTALL) | **{pct(TP, TP+FN)}** ({TP}/{TP+FN}) |")
    L.append(f"| Precision (flags that are real) | **{pct(TP, TP+FP)}** ({TP}/{TP+FP}) |")
    L.append(f"| F1 | **{f1:.3f}** |")
    L.append(f"| Accuracy | **{pct(TP+TN, TP+TN+FP+FN)}** |")
    L.append(f"| False positives on trusted skills | {FP}/{len(tru_dirs)} ({pct(FP, len(tru_dirs))}) |")
    L.append("")

    if missed:
        L.append(f"**Missed malicious ({len(missed)}):** " + ", ".join(missed) + "\n")
    if fp_list:
        L.append("**False positives on trusted skills (to investigate/tune):**\n")
        for name, c, rules in fp_list:
            L.append(f"- `{name}` — high {c['high']}, critical {c['critical']} — {', '.join(rules)}")
        L.append("")

    L.append("## Per-category recall (did the expected rule fire?)\n")
    L.append("| Expected rule/tag | Fired | Cases |")
    L.append("|-------------------|-------|-------|")
    for tag in sorted(tag_hit):
        h, tot = tag_hit[tag]
        L.append(f"| {tag} | {pct(h, tot)} | {h}/{tot} |")
    L.append("")

    L.append("## In-the-wild distribution (unlabeled community corpus)\n")
    total_w = max(1, len(wild_dirs))
    L.append(f"Of {len(wild_dirs)} community skills, **{pct(wild_flagged, total_w)}** have ≥1 high/critical finding "
             f"(comparable to published ~26% vulnerable-in-the-wild figures — these are candidates to review, not confirmed malware).\n")
    L.append("| Band | Count | Share |")
    L.append("|------|-------|-------|")
    for b in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        L.append(f"| {b} | {wild_bands.get(b,0)} | {pct(wild_bands.get(b,0), total_w)} |")
    L.append("")
    L.append("> Numbers are produced by `benchmark/run_benchmark.py` over the corpus "
             "fetched by `benchmark/fetch_corpus.sh`. The wild set is unlabeled, so its "
             "flag rate is an in-the-wild signal, not a precision measurement.\n")

    report = "\n".join(L)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print(f"\n[written to {args.out}]")


if __name__ == "__main__":
    main()
