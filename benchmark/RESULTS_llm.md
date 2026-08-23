# skillvet — full pipeline (static + LLM triage) vs static-only

The optional LLM stage (`--llm`) reasons over a skill's **code and instructions
together** and returns a verdict, confirming real static findings, dismissing
false positives, and catching semantic attacks (prompt injection, covert action,
code-that-contradicts-its-description) the static pass is blind to. This is the
layer MalSkillBench's authors argue is necessary — "detecting malicious skills
requires reasoning jointly over task intent, code, and instructions."

Measured on random MalSkillBench samples. Provider: `cli` (`claude -p`, a free
local agent — imperfect reliability). Flagged = static: ≥1 high/critical finding;
full: LLM verdict `malicious`|`vulnerable`.

| Run | LLM parse-success | Recall (static → full) | Benign FP (static → full) | F1 (static → full) |
|-----|-------------------|------------------------|---------------------------|--------------------|
| **C — stable (n=40, procs=3)** | **74/80 (93%)** | **50% → 90%** | **18% → 23%** | **0.60 → 0.85** |
| A (n=25, procs=10) | 28/50 (56%) | 52% → 92% | 16% → 16% | 0.62 → 0.89 |
| B (n=30, procs=5) | 45/60 (75%) | 50% → 73% | 17% → 20% | 0.60 → 0.76 |

**Run C is the headline** — low concurrency gave 93% LLM reliability, so almost
no fallbacks-to-static drag the number. It is the most trustworthy row.

## Honest reading (from the stable Run C)

- **Recall jumps** from **50% (static) to 90% (full)**. This is the whole point:
  static scanners collapse on prompt-injection and agent-control attacks; joint
  code+instruction reasoning recovers them.
- **F1 rises** from **0.60 to 0.85**, comparable to the strongest published full
  pipelines (NVIDIA SkillSpector cites ~87% precision for its static+LLM funnel;
  here precision is 80%, recall 90%). Same tier — we trade a little precision for
  more recall.
- **False positives rise honestly** (18% → 23%). The LLM dismisses some static
  false positives but is willing to call an imperfect-but-benign skill
  `vulnerable`, which counts as flagged here. Restricting "flagged" to
  `malicious`-only would cut FP at some cost to recall — a tunable knob, not a
  fixed limit.
- **Reliability matters:** at low concurrency the `claude -p` provider parsed 93%
  of calls, so Run C barely falls back to static. The earlier runs (A/B) show what
  happens when reliability drops. A dedicated API provider (`--llm-provider
  anthropic`/`openai`) is the production choice.

## Reproduce

```bash
python3 benchmark/eval_llm.py \
  --malware <malskillbench>/Dataset/Skills/malware \
  --benign  <malskillbench>/Dataset/Skills/benign \
  --n 30 --procs 5
```

Set `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) and pass `--llm-provider anthropic`
inside `scan_skill.py` for a production-grade, reliable run.
