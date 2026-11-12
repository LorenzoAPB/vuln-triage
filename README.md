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

## Results: v4 prompt, `gpt-5-mini`, held-out test

48 items (36 NVD records from March-April 2023 with NVD's own CVSS 3.1 vector and CWE, plus 12 synthetic thin, vague, and non-report items), 0 parse failures. Copied from [`evals/results.md`](evals/results.md).

| What | Result |
|---|---|
| Report vs noise: report precision / recall | 100% / 98% (42 reports) |
| Report vs noise: noise precision / recall | 86% / 100% (6 non-reports) |
| Severity published / accuracy | 100% of NVD items / 39% (13 over-scored, 9 under-scored) |
| Severity precision / recall: Critical, High, Medium, Low | 57% / 44%, 27% / 33%, 38% / 67%, 100% / 11% |
| Raw minus NVD base score | mean +0.07, mean absolute 1.87 |
| Severity within one band of NVD (None < Low < Medium < High < Critical) | 83% (30 of 36 NVD items) |
| Base score within 1.0 point of NVD | 36% (13 of 36 NVD items) |
| CWE exact / exact or direct parent-child / `unknown` | 47% / 67% / 3% |
| CVSS vector exact match | 17% |
| Per-metric agreement AV / AC / PR / UI / S / C / I / A | 81% / 89% / 78% / 86% / 94% / 50% / 56% / 72% |
| Thin and vague reports (6) | 6 low confidence, 5 with the vector withheld |
| Cost | about $0.0335 for 48 reports (Batch API) |

Against v2 on the same model and items, exact CWE matches went from 17% to 47% and the mean score bias from +1.31 to +0.07, but severity accuracy did not improve (44% raw in v2), within-one-band stayed at 83%, and within-1.0-point fell from 53% to 36%. Older runs and before/after tables: [`evals/history/`](evals/history). Dev-split ablation of every idea tried (retrieved examples, reasoning effort, a no-LLM nearest-neighbour baseline): [`evals/ablation.md`](evals/ablation.md).

## Limits and ethics

- Severity accuracy is far too low to act on unreviewed. The tool drafts; it does not replace human triage.
- Small splits (36 NVD items each in dev and test, so one item is about 3 points); v4 was tuned on dev only and scored 56% severity accuracy there vs 39% on test.
- Quote checks prove a quote exists, not that it supports the claim. NVD labels use knowledge the description lacks, so agreement with NVD is not the same as correctness.
- Data is public NVD records plus synthetic text written for this repo; nothing internal or customer-related. Running it on private reports sends their text to a third-party API, so check your disclosure agreements first.

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
python -m evals.batch --split test && python -m evals.run --split test --offline   # a new held-out run
```

Defaults: `--model gpt-5-mini`, `--prompt v4` (see `vuln-triage triage --help`). Logs go to `logs/triage.jsonl`.

## Prior work

- [AutoCVSS (EMNLP 2025 Industry Track)](https://aclanthology.org/2025.emnlp-industry.38.pdf): retrieving similar CVEs as few-shot examples; tested here as `exp-knn` (helped CWE on `gpt-4o-mini`, not severity).
- [Marchiori, Donadel, and Conti, "Can LLMs Classify CVEs?" (arXiv 2504.10713)](https://arxiv.org/abs/2504.10713): embedding methods beat LLMs on C/I/A; motivated the nearest-neighbour baseline.
- ["Knowledge-Driven Large Language Models for Automating CVSS Score Prediction" (ACM, 2025)](https://doi.org/10.1145/3733817.3762699): explicit scoring rules in the prompt, the approach the CVSS guidance follows.

## License

[MIT](LICENSE)
