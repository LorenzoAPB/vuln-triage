# vuln-triage progress

## Milestones
- [x] 0. Setup: OpenAI API key (env only, never committed), gh CLI logged in as LorenzoAPB, local git repo, Python 3.13 venv
- [x] 1. Pydantic schema + single structured-output call
- [x] 2. CVSS computed in code + guardrails (per-metric evidence, verified quotes, unknowns, thin reports, non-report refusal)
- [x] 3. Human approve/edit/reject CLI (`vuln-triage triage FILE`) + JSONL telemetry in logs/
- [x] 4. Eval set (48 items: 36 NVD, 12 synthetic) + metrics, one command (`python -m evals.run`)
- [x] 5. pytest (28 tests, API mocked) + GitHub Actions (ruff, pytest, offline eval replay with --check, optional live smoke)
- [x] 6. README with architecture, design choices, results, limits, ethics; demo GIF; MIT license

## Session log
- 2026-11-11: Milestone 0 done. Deps: openai 3.49.0, pydantic 2.14.3, cvss 3.6 (RedHat lib), pytest, ruff.
- 2026-11-11: Milestone 1. gpt-4.1-mini on Log4Shell: CWE-94 vs NVD CWE-917; vector 'unknown' (prompt too strict). Non-report correctly flagged. Private repo created.
- 2026-11-11: Milestones 2-6.
  - Per-metric CVSS evidence wired into guardrails. Thin XSS report first came back 9.8 Critical from guesses, so thin reports (and vectors with more than 4 unverified metrics) now withhold the vector.
  - Model history: gpt-4.1-mini is deprecated; the account is limited to 50 requests per model per day and 10 per minute. The first full eval ran on gpt-5.4-nano (v1 schema) and abstained on every CVSS vector (snapshot in docs/eval-v1-gpt-5.4-nano.md). Schema v2 removed 'unknown' from CVSS metrics; second full eval on gpt-5-mini (minimal reasoning). 19 partial gpt-5.4-mini responses are in .cache/ (not committed).
  - Live spend this session: about $0.10 in total (eval v2 $0.0623, eval v1 $0.0328, plus a few single calls).
  - Results (gpt-5-mini): report detection 100% precision / 98% recall; severity accuracy 42% when published (67% coverage), raw 44% with 19 over-scored vs 1 under; CWE exact 17% (75% unknown).

## Open questions / next steps
- Over-scoring: try a prompt that states the CVSS "assume the reasonable worst case" rule explicitly, or few-shot NVD examples, and measure.
- Evidence relevance: the same quote is often reused for 4+ metrics. Options: require distinct quotes per metric, or a second model call that judges whether each quote supports its metric.
- CWE: allow the model to name a CWE from the weakness described, even without a quote naming it.
- Rerun the eval on gpt-5.4-mini once the daily limit allows (needs 48 requests), for a real model comparison.

## Interview prep topics
- Why structured outputs, and what strict mode guarantees (and does not: values can still be wrong).
- Why the score is computed in code; how CVSS v3.1 base score math works (impact subscore, scope change).
- Reading a vector from prose metric by metric (the weak spot from milestone 1): which sentences support AV, PR, UI, C/I/A.
- Why per-metric evidence, and why the eval showed it does not catch bad vectors.
- How the first eval run changed the schema (abstention vs. proposal + code decision).
- Precision/recall per class, confusion matrices, why precision is undefined when a class is never predicted.
- Label quality: NVD analysts use outside knowledge; what "agreement" means.
- Caching and replayable evals in CI; cost estimation from token usage.
