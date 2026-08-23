#!/usr/bin/env python3
"""Dump the wild skills our scanner flags high/critical, for manual labeling."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "skills", "skillvet", "scripts")))
import scan_skill as S

def find_skill_dirs(root):
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__", "node_modules")]
        if any(f.lower() == "skill.md" for f in fn):
            out.append(dp)
    return out

def scan_one(d):
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
    score = S.risk_score(dd, S._ships_executable(d))
    band, _ = S.score_band(score)
    return counts, score, band, dd

def main():
    roots = sys.argv[1:]
    flagged = []
    for root in roots:
        for d in find_skill_dirs(root):
            counts, score, band, dd = scan_one(d)
            if counts["high"] + counts["critical"] > 0:
                flagged.append(dict(
                    path=d, score=score, band=band, counts=counts,
                    findings=[dict(rule=f["rule"], severity=f["severity"], file=f["file"],
                                   line=f["line"], title=f["title"], snippet=f.get("snippet","")[:160])
                              for f in dd if f["severity"] in ("high", "critical")]))
    out = os.path.join(HERE, "..", ".foreman", "scratch", "wild_flagged.json")
    out = os.path.normpath(out)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(flagged, f, indent=2, ensure_ascii=False)
    print(f"{len(flagged)} flagged wild skills written to {out}")

if __name__ == "__main__":
    main()
