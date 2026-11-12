# Eval history

Snapshots of every eval run, each labeled with the exact model and prompt/schema version that produced it (also stored as `prompt` and `metrics.model` in each JSON), kept because each one changed the design. JSON files hold the raw rows;
`python -m evals.compare BEFORE.json AFTER.json` recomputes a before/after table from them with the current
metric code. Runs on an older prompt or schema cannot be replayed against the current code (both are part
of the cache key).

| File | Split | Prompt | Model | What it showed |
|---|---|---|---|---|
| `v1-test-gpt-5.4-nano` | test | v1: every CVSS metric may be `unknown` | gpt-5.4-nano | Abstained on every vector |
| `v2-test-gpt-5-mini` | test | v2: full vector always proposed, per-metric quotes | gpt-5-mini | Over-scoring, CWE mostly `unknown` |
| `dev-v2-gpt-5-nano` | dev | v2 | gpt-5-nano | Dev baseline |
| `dev-v3a-gpt-5-nano` | dev | v3 draft: CWE knowledge allowed, CVSS guidance, quote-reuse limit | gpt-5-nano | Model wrote explanations into quote fields |
| `dev-v3b-gpt-5-nano` | dev | v3: plus "quotes are verbatim" and "a crash affects A only" | gpt-5-nano | Final v3 dev results on the old 15-item dev split |
| `v3-test-gpt-4o-mini` | test | v3 | gpt-4o-mini | Run on gpt-4o-mini because gpt-5-mini's daily quota was used up; not comparable to the v2 row (different model) |
| `v3-test-gpt-5-mini` | test | v3 | gpt-5-mini | Same-model baseline for v4 (Batch API). CWE exact 17% -> 47% vs v2; bias +1.31 -> +0.07 |
| `v4-test-gpt-5-mini` | test | v4: v3 prompt, inferred vectors published as provisional | gpt-5-mini | Current test results (`../results.md`); same responses as v3 |
| `v4-test-gpt-4o-mini` | test | v4 | gpt-4o-mini | Same responses as `v3-test-gpt-4o-mini`; coverage 8% -> 100% |
| `dev-v5-gpt-5-mini` | dev (NVD descriptions) | v5 | gpt-5-mini | The write-up prompt on NVD descriptions: 44% severity vs 56% for v4, so v4 stays the default |
| `compare-writeups-vs-nvd-v5-gpt-5-mini.md` | writeups-test | v5 | gpt-5-mini | Same CVEs: Exploit-DB write-up vs NVD description |
| `compare-*.md` | test | - | same model in both columns | Generated before/after tables (`python -m evals.compare`) |

The dev split grew from 15 to 39 items for v4 (`../build_dataset.py`); the `dev-*-gpt-5-nano` snapshots use the old 15-item split. v4's dev iteration is in `../ablation.md`.

