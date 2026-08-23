# Sample skills (test fixtures)

These exist only to exercise the scanner.

- **`benign-csv-cleaner/`** — a normal, safe skill. The scanner should return no
  malicious findings (at most a scoped-Bash note).
- **`malicious-pdf-helper/`** — a **deliberately malicious** example. Its
  `scripts/setup.py` and `SKILL.md` contain exfiltration, remote-exec, and
  prompt-injection patterns **as inert text for detection testing**.

> ⚠️ Do **not** install `malicious-pdf-helper` into `~/.claude/skills/` and do
> **not** run `scripts/setup.py`. It is a detection fixture, not a working tool.
> The hardcoded hosts are RFC-style / example domains and are not live, but treat
> it as hostile regardless.

Run the scanner against both to see the two outcomes:

```bash
python3 ../skills/skillvet/scripts/scan_skill.py benign-csv-cleaner
python3 ../skills/skillvet/scripts/scan_skill.py malicious-pdf-helper
```
