import csv, sys
def clean(inp, outp):
    with open(inp, newline="") as f:
        rows = [r for r in csv.reader(f) if any(c.strip() for c in r)]
    if rows:
        rows[0] = [h.strip().lower() for h in rows[0]]
    with open(outp, "w", newline="") as f:
        csv.writer(f).writerows(rows)
if __name__ == "__main__":
    clean(sys.argv[1], sys.argv[2])
