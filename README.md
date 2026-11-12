# vuln-triage

[![CI](https://github.com/LorenzoAPB/vuln-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/LorenzoAPB/vuln-triage/actions/workflows/ci.yml)

A PSIRT inbox mixes real advisories, one-line "found an XSS" emails, and messages that are not reports at all. Each one needs a first pass: affected product, CWE, CVSS v3.1 vector, next step. This tool has an LLM draft that pass, has code check every claim it can, and leaves the decision to a human analyst.

![Demo: the model drafts a provisional 4.3 Medium for an ArubaOS report; the analyst corrects the vector to 2.4 Low and the CWE to CWE-613, then rejects a two-line XSS report](docs/demo.gif)

<sub>Runs with the defaults (`gpt-5-mini`, prompt v4) and replays recorded responses, so it makes no API calls.</sub>

## How it works

```mermaid
flowchart LR
    R[Report text] --> M["Model<br/>structured output<br/>(ModelTriage schema)"]
    M --> G["Guardrails in code<br/>verify quotes · compute CVSS score<br/>flag inferred metrics · cap confidence"]
    G --> H{"Analyst<br/>approve / edit / reject"}
    H --> L[("logs/triage.jsonl<br/>tokens · cost · flags · decision · overrides")]
    M <-.-> C[("disk cache /<br/>eval recordings")]
```

- **Structured outputs.** A strict Pydantic schema ([`schema.py`](vuln_triage/schema.py)) means every response parses and every CVSS metric is a legal value. Refusals and truncation surface as one `TriageError`.
- **Arithmetic in code.** The model proposes the eight base metrics; the [`cvss`](https://pypi.org/project/cvss/) library computes the score and severity.
- **Every claim cites the report.** Each metric, the CWE, and each evidence item carry a quote that code checks against the report text ([`guardrails.py`](vuln_triage/guardrails.py)). Unverified quotes are dropped and flagged; a CWE without a verified quote becomes `unknown`.
- **Inferred metrics are labeled, not hidden.** A metric without a verified quote counts as inferred (so does a quote cited for more than three metrics). A vector with more than four inferred metrics is published as `cvss_provisional`, with the inferred metrics listed and confidence set to low. Reports under 120 characters get no score.
- **Score what the report states.** The prompt ([`triage.py`](vuln_triage/triage.py)) spells out CVSS v3.1 practice (C/I/A High only for total loss, a crash affects availability only) and lets the model use CWE knowledge to classify the weakness.
- **Non-reports are refused**, and confidence is low/medium/high, only ever lowered by code.
- **Human in the loop, with a record.** The analyst approves, edits (CWE, vector, severity, product), or rejects. Each run logs model, prompt version, tokens, cost, flags, the decision, and every field the human changed ([`cli.py`](vuln_triage/cli.py)).
- **Cheap and replayable.** Default model `gpt-5-mini` at minimal reasoning effort. Responses are cached by model, prompt, schema, and input; evals run through the Batch API ([`evals/batch.py`](evals/batch.py)) at half price, and CI replays every reported number.

## Results: researcher write-ups, v5 prompt, `gpt-5-mini`, held-out test

Real inbox reports look like researcher write-ups, not NVD's one-paragraph summaries, so the main eval uses public [Exploit-DB](https://www.exploit-db.com) write-ups ([`evals/build_writeups.py`](evals/build_writeups.py)): prose entries that name exactly one CVE, labeled with NVD's primary CVSS 3.1 vector and CWE. CVE ids, CWE ids, CVSS and severity lines, and NVD/MITRE links are stripped from the text. Fixed selection rule: 10 (dev) or 15 (test) per severity, at most 2 per CWE per severity; dev = CVE-2020/2021, test = CVE-2022/2023. Exploit-DB has almost no entries NVD rates Low, so the split covers Medium, High, and Critical.

57 items (45 write-ups plus the same 12 synthetic thin, vague, and non-report items), run once on 2026-11-11, 0 parse failures. Copied from [`evals/writeups_results.md`](evals/writeups_results.md).

| What | Result |
|---|---|
| Report vs noise: report precision / recall | 100% / 98% (51 reports) |
| Report vs noise: noise precision / recall | 86% / 100% (6 non-reports) |
| Severity published / accuracy | 100% of write-ups / 51% (6 over-scored, 16 under-scored) |
| Severity precision / recall: Critical, High, Medium | 73% / 53%, 44% / 27%, 46% / 73% |
| Raw minus NVD base score | mean -0.94, mean absolute 1.53 |
| Severity within one band of NVD | 87% |
| Base score within 1.0 point of NVD | 47% |
| CWE exact / exact or direct parent-child / `unknown` | 56% / 62% / 18% |
| CVSS vector exact match | 20% |
| Per-metric agreement AV / AC / PR / UI / S / C / I / A | 96% / 96% / 80% / 89% / 93% / 44% / 51% / 60% |
| Thin and vague reports (6) | 6 low confidence, 5 with the vector withheld |
| Cost | about $0.0542 for 57 reports (Batch API) |

**Write-up vs NVD description, same 45 CVEs** (both `gpt-5-mini`, prompt v5; [`evals/history/compare-writeups-vs-nvd-v5-gpt-5-mini.md`](evals/history/compare-writeups-vs-nvd-v5-gpt-5-mini.md)): severity correct over all items 51% for both. The write-ups get every item scored (NVD descriptions: 87%, the rest are under 120 characters and withheld), score within 1.0 point more often (47% vs 44%), and recall Critical better (53% vs 40%); the NVD descriptions give fewer `unknown` CWEs (7% vs 18%), better lenient CWE (69% vs 62%), and a lower MAE (1.42 vs 1.53). Longer, messier text did not make the model more accurate overall.

**Tuning (dev only, 30 write-ups, `gpt-5-mini`; [`evals/writeups_ablation.md`](evals/writeups_ablation.md)).** v5 adds rules for reading exploit code and HTTP requests (login steps and session cookies mean PR:L, a shell means C/I/A:H). Against v4 on dev: severity 47% vs 43%, within 1.0 point 47% vs 37%, CWE exact 53% vs 60%; a no-LLM nearest-neighbour vote scored 40%. Quote checks now ignore comment markers (`#`, `//`) at line starts, so a sentence wrapped across commented lines verifies; this did not change any earlier result. v5 is worse on NVD descriptions (dev: 44% vs 56% for v4, [`evals/history/dev-v5-gpt-5-mini.json`](evals/history/dev-v5-gpt-5-mini.json)), so the CLI default stays v4; pass `--prompt v5` for write-ups.

### Earlier: NVD descriptions, v4 prompt, `gpt-5-mini`, held-out test

36 NVD records from March-April 2023 plus the 12 synthetic items ([`evals/results.md`](evals/results.md)): severity accuracy 39% (all published), within one band 83%, within 1.0 point 36%, CWE exact 47%, vector exact 17%, about $0.0335. Older runs: [`evals/history/`](evals/history); dev ablation: [`evals/ablation.md`](evals/ablation.md).

## Limits and ethics

- Severity accuracy is far too low to act on unreviewed. The tool drafts; it does not replace human triage.
- Small splits (30 dev and 45 test write-ups; 36 + 36 NVD items), so one item moves a result by 2-3 points and the v4/v5 dev differences are within noise. No Low-severity write-ups.
- Labels are NVD's, assigned from NVD's description; the write-up text may support a different but defensible vector.
- Quote checks prove a quote exists, not that it supports the claim. NVD labels use knowledge the description lacks, so agreement with NVD is not the same as correctness.
- Data is public: NVD records, Exploit-DB write-ups, and synthetic text written for this repo; nothing internal or customer-related. HackerOne disclosed reports and Full-Disclosure posts were not used (no scriptable public export); GitHub advisories were checked and skipped (too few Low items, and NVD often copies their text). Running it on private reports sends their text to a third-party API, so check your disclosure agreements first.

## Run it

Requires Python 3.12+.

```bash
git clone https://github.com/LorenzoAPB/vuln-triage && cd vuln-triage
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

make test    # pytest, API mocked
make eval    # replay recorded eval responses and the ablation; free and deterministic

export OPENAI_API_KEY=...   # only needed for new reports
vuln-triage triage examples/cve-2021-44228.txt --out triaged.json
vuln-triage triage report.txt --prompt v5   # a researcher write-up
make writeups   # rebuild the write-up splits from Exploit-DB and NVD's yearly feeds
```

Defaults: `--model gpt-5-mini`, `--prompt v4` (see `vuln-triage triage --help`). Logs go to `logs/triage.jsonl`.

## Prior work

- [AutoCVSS (EMNLP 2025 Industry Track)](https://aclanthology.org/2025.emnlp-industry.38.pdf): retrieving similar CVEs as few-shot examples; tested here as `exp-knn` (helped CWE on `gpt-4o-mini`, not severity).
- [Marchiori, Donadel, and Conti, "Can LLMs Classify CVEs?" (arXiv 2504.10713)](https://arxiv.org/abs/2504.10713): embedding methods beat LLMs on C/I/A; motivated the nearest-neighbour baseline.
- ["Knowledge-Driven Large Language Models for Automating CVSS Score Prediction" (ACM, 2025)](https://doi.org/10.1145/3733817.3762699): explicit scoring rules in the prompt, the approach the CVSS guidance follows.

## License

[MIT](LICENSE)
