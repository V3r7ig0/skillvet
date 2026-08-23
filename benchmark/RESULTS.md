# skillvet benchmark results

_Scanned 44 malicious + 20 trusted + 1665 in-the-wild skills in 66.0s._

Decision rule: a skill is **flagged** when it has ≥1 high or critical finding.

## Headline metrics (trusted = negatives, malicious = positives)

| Metric | Value |
|--------|-------|
| Detection recall (≥1 finding of any severity) | **97.7%** (43/44) |
| Block recall (≥1 high/critical → DO NOT INSTALL) | **86.4%** (38/44) |
| Precision (flags that are real) | **95.0%** (38/40) |
| F1 | **0.905** |
| Accuracy | **87.5%** |
| False positives on trusted skills | 2/20 (10.0%) |

**Missed malicious (6):** exfil-clipboard, subtle-trigger-abuse, subtle-autonomy, sc-typosquat, subtle-shell-true, chr-chain

**False positives on trusted skills (to investigate/tune):**

- `skills/algorithmic-art` — high 1, critical 0 — CE-DYNAMIC-EXEC, TM-UNSAFE-DEFAULT
- `skills/claude-api` — high 5, critical 0 — FM-IMPERSONATION, MP-PERSIST-INSTRUCTION, PE-SUDO, PI-OVERRIDE, PI-TOOL-COERCE, PI-WHITESPACE-PAD

## Per-category recall (did the expected rule fire?)

| Expected rule/tag | Fired | Cases |
|-------------------|-------|-------|
| AR-DISCLAIMER-SUPPRESS | 100.0% | 1/1 |
| AR-REFUSAL-SUPPRESS | 100.0% | 1/1 |
| AR-SAFETY-NULLIFY | 0.0% | 0/1 |
| CE-CHR-CHAIN | 100.0% | 1/1 |
| CE-CURL-CHMOD-RUN | 100.0% | 1/1 |
| CE-DESTRUCTIVE | 100.0% | 1/1 |
| CE-DYNAMIC-EXEC | 100.0% | 1/1 |
| CE-MARSHAL-PICKLE | 100.0% | 1/1 |
| CE-OBFUSCATION-B64 | 0.0% | 0/1 |
| CE-OS-SYSTEM | 100.0% | 1/1 |
| CE-POWERSHELL-ENC | 100.0% | 1/1 |
| CE-REMOTE-EXEC | 100.0% | 3/3 |
| CE-REVERSE-SHELL | 100.0% | 1/1 |
| CE-SHELL-TRUE | 100.0% | 1/1 |
| CE-ZLIB-EXEC | 0.0% | 0/1 |
| EA-AUTONOMY | 100.0% | 1/1 |
| EX-CLIPBOARD | 100.0% | 1/1 |
| EX-CONTEXT-LEAK | 100.0% | 1/1 |
| EX-DNS | 100.0% | 1/1 |
| EX-EMAIL | 100.0% | 1/1 |
| EX-ENV-HARVEST | 100.0% | 1/1 |
| EX-GIT-REMOTE | 100.0% | 1/1 |
| EX-NET-POST | 100.0% | 4/4 |
| EX-SECRET-FILES | 100.0% | 3/3 |
| EX-TAINT-EXFIL | 0.0% | 0/1 |
| EX-WEBHOOK | 100.0% | 1/1 |
| FM-BROAD-TOOLS | 100.0% | 1/1 |
| FM-CTX-EXFIL | 100.0% | 1/1 |
| FM-DYNAMIC-SHELL | 100.0% | 1/1 |
| FM-IMPERSONATION | 0.0% | 0/1 |
| MCP-TOOL-POISON | 100.0% | 1/1 |
| MCP-WILDCARD | 100.0% | 1/1 |
| MP-PERSIST-INSTRUCTION | 100.0% | 1/1 |
| PE-AUTHKEYS-WRITE | 100.0% | 1/1 |
| PE-PERSIST | 100.0% | 2/2 |
| PE-SUDO | 100.0% | 1/1 |
| PE-SUDOERS | 100.0% | 1/1 |
| PI-DECODE-FOLLOW | 100.0% | 1/1 |
| PI-HIDDEN-HTML | 100.0% | 1/1 |
| PI-HIDDEN-UNICODE | 100.0% | 1/1 |
| PI-MODE-SWITCH | 100.0% | 1/1 |
| PI-OVERRIDE | 100.0% | 1/1 |
| PI-SECRECY | 100.0% | 1/1 |
| RA-SELFMOD | 100.0% | 1/1 |
| SC-INDEX-OVERRIDE | 100.0% | 1/1 |
| SC-PIP-URL | 100.0% | 1/1 |
| SC-POSTINSTALL | 100.0% | 1/1 |
| SC-RAW-FETCH-HOST | 100.0% | 1/1 |
| SC-REMOTE-FETCH | 0.0% | 0/1 |
| SC-TYPOSQUAT | 100.0% | 1/1 |
| SP-LEAK | 100.0% | 1/1 |
| TR-BROAD | 0.0% | 0/1 |
| YR-Skillvet_Base64_Payload_Exec | 100.0% | 1/1 |
| YR-Skillvet_Reverse_Shell | 100.0% | 1/1 |

## In-the-wild distribution (unlabeled community corpus)

Of 1665 community skills, **2.3%** have ≥1 high/critical finding (comparable to published ~26% vulnerable-in-the-wild figures — these are candidates to review, not confirmed malware).

| Band | Count | Share |
|------|-------|-------|
| LOW | 1583 | 95.1% |
| MEDIUM | 47 | 2.8% |
| HIGH | 9 | 0.5% |
| CRITICAL | 26 | 1.6% |

> Numbers are produced by `benchmark/run_benchmark.py` over the corpus fetched by `benchmark/fetch_corpus.sh`. The wild set is unlabeled, so its flag rate is an in-the-wild signal, not a precision measurement.
