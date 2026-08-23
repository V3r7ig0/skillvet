#!/usr/bin/env python3
"""
Measure the FULL pipeline (static + LLM triage) vs static-only on a labeled
sample. LLM decision: overall_verdict in {malicious, vulnerable} => flagged.

Usage:
  python3 benchmark/eval_llm.py --malware <dir> --benign <dir> --n 40 --procs 8
"""
import argparse, os, sys, time
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
SCR = os.path.normpath(os.path.join(HERE, "..", "skills", "skillvet", "scripts"))
sys.path.insert(0, SCR)
import scan_skill as S
import llm_triage


def first_skill_dirs(root, n):
    out = []
    for dp, dn, fn in sorted(os.walk(root)):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__", "node_modules")]
        if any(f.lower() == "skill.md" for f in fn):
            out.append(dp)
            if len(out) >= n:
                break
    return out


def one(d):
    try:
        findings, _, _ = S.scan_dir(d)
        S.check_frontmatter(d, findings)
        S.scan_yara(d, findings)
        seen, dd = set(), []
        for f in findings:
            k = (f["rule"], f["file"], f["line"])
            if k not in seen:
                seen.add(k); dd.append(f)
        counts = S.summarize(dd)
        static_flag = (counts["high"] + counts["critical"]) > 0
        j = llm_triage.triage(d, dd, provider="cli", timeout=90)
        if j:
            v = j.get("overall_verdict")
            full_flag = v in ("malicious", "vulnerable")
        else:
            full_flag = static_flag  # LLM failed -> fall back to static
        return static_flag, full_flag, (j is not None)
    except Exception:
        return False, False, False


def pct(n, d):
    return f"{(100.0*n/d):.1f}%" if d else "—"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malware", required=True)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--out", default=os.path.join(HERE, "RESULTS_llm.md"))
    a = ap.parse_args()

    mal = first_skill_dirs(a.malware, a.n)
    ben = first_skill_dirs(a.benign, a.n)
    t0 = time.time()
    with Pool(a.procs) as p:
        mr = p.map(one, mal)
        br = p.map(one, ben)
    dt = time.time() - t0

    def rates(res):
        s = sum(1 for x in res if x[0])
        f = sum(1 for x in res if x[1])
        ok = sum(1 for x in res if x[2])
        return s, f, ok

    ms, mf, mok = rates(mr)
    bs, bf, bok = rates(br)
    N = len(mal)
    M = len(ben)

    L = []
    L.append("# skillvet — full pipeline (static + LLM triage) vs static-only\n")
    L.append(f"_Sample: {N} malware + {M} benign from MalSkillBench. LLM provider: cli "
             f"(claude -p). LLM parse-success: {mok+bok}/{N+M}. Ran in {dt:.0f}s._\n")
    L.append("Flagged = static: ≥1 high/critical finding; full: LLM verdict malicious|vulnerable.\n")
    L.append("| Metric | Static only | Static + LLM |")
    L.append("|--------|-------------|--------------|")
    L.append(f"| Recall (malware flagged) | {pct(ms,N)} ({ms}/{N}) | **{pct(mf,N)}** ({mf}/{N}) |")
    L.append(f"| Benign false-positive rate | {pct(bs,M)} ({bs}/{M}) | **{pct(bf,M)}** ({bf}/{M}) |")
    prec_s = ms/(ms+bs) if (ms+bs) else 0
    prec_f = mf/(mf+bf) if (mf+bf) else 0
    L.append(f"| Precision | {pct(ms,ms+bs)} | **{pct(mf,mf+bf)}** |")
    def f1(p, r):
        return 2*p*r/(p+r) if (p+r) else 0
    L.append(f"| F1 | {f1(prec_s, ms/N):.3f} | **{f1(prec_f, mf/N):.3f}** |")
    report = "\n".join(L)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print(f"\n[written to {a.out}]")


if __name__ == "__main__":
    main()
