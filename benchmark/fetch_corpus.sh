#!/usr/bin/env bash
# Fetch the benchmark corpus (public skill repos) into benchmark/corpus/.
# The corpus is NOT committed (see .gitignore) — it's other people's code,
# pulled fresh so anyone can reproduce the numbers in RESULTS.md.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/corpus"
mkdir -p "$DIR"

clone() {  # <url> <dest>
  if [ -d "$DIR/$2/.git" ]; then
    echo "already have $2"
  else
    git clone --depth 1 "$1" "$DIR/$2"
  fi
}

# trusted (known-good) — official Anthropic skills → used as negatives
clone https://github.com/anthropics/skills.git trusted

# in-the-wild (unlabeled community collections) → reported as a flag-rate signal
clone https://github.com/alirezarezvani/claude-skills.git wild-1
clone https://github.com/ComposioHQ/awesome-claude-skills.git wild-2

echo
echo "Corpus ready in $DIR"
echo "Now run the crafted-fixture + wild benchmark:"
echo "  python3 benchmark/run_benchmark.py \\"
echo "    --trusted \"$DIR/trusted\" \\"
echo "    --wild \"$DIR/wild-1\" --wild \"$DIR/wild-2\" \\"
echo "    --out benchmark/RESULTS.md"
echo
echo "--- Optional: EXTERNAL labeled dataset (the honest headline numbers) ---"
echo "MalSkillBench is ~8 GB and licensed for ACADEMIC RESEARCH ONLY — fetch it yourself:"
echo "  git clone --depth 1 https://github.com/lxyeternal/MalSkillBench.git \"$DIR/malskillbench\""
echo "  python3 benchmark/eval_labeled.py \\"
echo "    --malware \"$DIR/malskillbench/Dataset/Skills/malware\" \\"
echo "    --benign  \"$DIR/malskillbench/Dataset/Skills/benign\" \\"
echo "    --out benchmark/RESULTS_external.md"
echo "Smaller real malicious samples (cloneable):"
echo "  git clone --depth 1 https://github.com/snyk-labs/toxicskills-goof.git \"$DIR/mal-snyk\""
echo "  git clone --depth 1 https://github.com/NVIDIA/SkillSpector.git \"$DIR/mal-nvidia\"  # tests/fixtures/malicious_skill"
