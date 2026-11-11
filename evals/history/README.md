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
| `dev-v3b-gpt-5-nano` | dev | v3: plus "quotes are verbatim" and "a crash affects A only" | gpt-5-nano | Current dev results (`../dev_results.md`) |
| `v3-test-gpt-4o-mini` | test | v3 | gpt-4o-mini | Current test results (`../results.md`). Run on gpt-4o-mini because gpt-5-mini's daily quota was used up; not comparable to the v2 row (different model) |
