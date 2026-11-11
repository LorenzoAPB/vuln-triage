# vuln-triage

[![CI](https://github.com/LorenzoAPB/vuln-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/LorenzoAPB/vuln-triage/actions/workflows/ci.yml)

An LLM drafts the triage of a security vulnerability report, code checks every claim it can, and a human approves, edits, or rejects the draft. Nothing is final until a person decides.

![Demo: the model over-scores an ArubaOS report as 8.8 High; the analyst corrects the vector to 2.4 Low and rejects a two-line XSS report](docs/demo.gif)

<sub>Recorded with the v2 prompt (see [Results](#results)).</sub>

## The problem

A PSIRT inbox mixes detailed advisories, one-line "found an XSS, please fix" emails, scanner output, and messages that are not vulnerability reports at all. For each one, an analyst has to work out what is affected, map the weakness to a CWE, read a CVSS v3.1 vector out of prose, and decide what happens next. That first pass is slow and repetitive, and its output feeds severity SLAs, so mistakes are expensive in both directions.

A language model can write that first draft in seconds. The risks are the familiar ones: confident numbers with nothing behind them, quotes the reporter never wrote, and a triage forced onto text that was never a report. This project is a small, inspectable answer to the question: how much of the first pass can a cheap model draft, and what has to stay in code and with a human?

## How it works

```mermaid
flowchart LR
    R[Report text] --> M["Model<br/>structured output<br/>(ModelTriage schema)"]
    M --> G["Guardrails in code<br/>verify quotes · compute CVSS score<br/>cap confidence · withhold weak vectors"]
    G --> H{"Analyst<br/>approve / edit / reject"}
    H --> L[("logs/triage.jsonl<br/>tokens · cost · flags · decision · overrides")]
    M <-.-> C[("disk cache /<br/>eval recordings")]
```

| File | What it does |
|---|---|
| [`vuln_triage/schema.py`](vuln_triage/schema.py) | `ModelTriage`: what the model may return. `TriageResult`: the draft a human reviews. |
| [`vuln_triage/triage.py`](vuln_triage/triage.py) | One Responses API call with structured outputs, a disk cache, token usage, and cost. |
| [`vuln_triage/guardrails.py`](vuln_triage/guardrails.py) | `finalize()`: turns the model's proposal into a draft, trusting nothing that code can check. |
| [`vuln_triage/cli.py`](vuln_triage/cli.py) | The review loop and the JSONL log. |
| [`evals/`](evals) | A 15-item dev split for iteration, a 48-item held-out test split, metric code, recorded responses, and [history](evals/history) of every run. |

## Design choices

**Structured outputs instead of "please answer in JSON".** The Pydantic schema is sent as a strict JSON schema, so every response parses, every field is present, and enum fields (each CVSS metric, the confidence level) can only take legal values. Parsing errors, refusals, and truncation surface as one `TriageError` and are logged as `parse_failure`.

**The CVSS score is computed in code.** The model proposes the eight base metrics; the [`cvss`](https://pypi.org/project/cvss/) library computes the score, and the severity band follows from it. A model can easily say "9.8" for a vector that scores 7.5. Arithmetic is not its job.

**Per-metric evidence.** Each metric comes with the exact report text that supports it, or `''` when the model is inferring. Code checks every quote against the report (case- and whitespace-insensitive substring match). A metric counts as guessed if its quote is missing, is not in the report, or is the same sentence cited for more than three metrics (one sentence cannot carry most of a vector; the v2 eval found the model doing exactly that). One guess caps confidence at medium. More than four guesses, or a report under 120 characters, and the vector is withheld: the analyst sees the model's guess, labeled as a guess, but no score is published.

**Score what the report states, not the worst case.** The prompt spells out standard CVSS v3.1 practice: C/I/A are High only for total loss, a crash affects availability only, PR:N needs the report to say or clearly imply no account, S:C needs a crossed security boundary. This targets the over-scoring the v2 eval measured.

**Every claim cites the report.** Evidence quotes that do not appear in the report are dropped and flagged (`dropped_N_unverified_quotes`). No verified evidence at all means low confidence.

**CWE is classification, so the model may use its CWE knowledge.** Facts about the product come only from the report, but mapping "a missing buffer size check" to CWE-787 is classification, which is what an NVD analyst does. The model gives the most specific CWE plus a `cwe_quote` describing the weakness; if that quote is not in the report, code resets the CWE to `unknown` (`cwe_without_evidence`). In v2, forbidding outside knowledge made the model answer `unknown` for 75% of CWEs.

**`unknown` is a legal answer, except for CVSS metrics.** Strict schemas make every field required, so without an explicit `unknown` the model is pushed to invent a CWE or a product. CVSS metrics are the exception, for a reason found in the eval: when each metric could be `unknown`, the model left at least one unknown on every NVD item, so no severity was ever produced ([first run](evals/history/v1-test-gpt-5.4-nano.md)). Now the model always proposes, and code decides from the evidence whether to publish.

**Three confidence levels, not a percentage.** "0.87" invites false precision. Low, medium, and high are levels a reviewer can check, and code can lower them (never raise them) based on what it verified.

**Non-reports are refused.** `is_vulnerability_report: false` short-circuits to an empty draft with "route back to sender" as the next step, instead of a CVSS score for an offsite reminder.

**Human in the loop, with a record.** The analyst can edit the CWE, the vector (the score and severity are recomputed), the severity, and the product, or reject with a reason. Each run logs model, latency, tokens, estimated cost, guardrail flags, the decision, and every field the human changed with the model's value next to theirs. Those overrides are the data you would use to improve the prompt.

**Cheap model, cached calls.** `gpt-5-mini` at minimal reasoning effort costs about a tenth of a cent per report. Responses are cached on disk, keyed by model, prompt, schema, and report text, so re-runs are free and the eval replays exactly. Prices live in one constant (`PRICES_PER_MTOK`) with the source URL and the date they were checked.

## Evaluation method

Two splits, both built by the same fixed rule in [`build_dataset.py`](evals/build_dataset.py) (NVD records where NVD itself assigned the CVSS 3.1 vector and a specific CWE, 150-900 character descriptions, no SAP, first N per severity with distinct CWEs) from different publication windows:

| Split | Items | Window | Used for |
|---|---|---|---|
| dev | 12 NVD (3 per severity) + 3 synthetic | June-July 2023 | All prompt and guardrail iteration |
| test | 36 NVD (9 per severity) + 12 synthetic | March-April 2023 | Held out; run once per finished version |

Labels are NVD's CVSS 3.1 vector and primary CWE. The lenient CWE metric counts a direct parent or child in MITRE's Research view (CWE-1000, from [`cwe_parents.json`](evals/cwe_parents.json), built by [`build_cwe_tree.py`](evals/build_cwe_tree.py)). Every number below is generated by `python -m evals.run` or `python -m evals.compare`; snapshots of each run are in [`evals/history`](evals/history).

## Results

### Current held-out numbers: v2 prompt, `gpt-5-mini`

Test split, 48 items, 0 parse failures. Full tables and per-item output: [`evals/history/v2-test-gpt-5-mini.md`](evals/history/v2-test-gpt-5-mini.md).

| What | Result |
|---|---|
| Report vs noise: report precision / recall | 100% / 98% (42 reports) |
| Report vs noise: noise precision / recall | 86% / 100% (6 non-reports) |
| Severity published (vector passed the guardrails) | 67% of NVD items |
| Severity accuracy when published | 42% |
| Severity accuracy of the raw model vector, no guardrails | 44% (19 over-scored, 1 under-scored) |
| Raw minus NVD base score | mean +1.31, mean absolute 1.49 |
| CWE exact match with NVD primary CWE | 17% (75% answered `unknown`) |
| CWE exact or direct parent/child (lenient) | 17% |
| CVSS vector exact match, raw model vector | 22% |
| Per-metric agreement AV / AC / PR / UI / S / C / I / A | 69% / 89% / 81% / 89% / 81% / 64% / 64% / 78% |
| Thin and vague reports (6) | 6 low confidence, 5 with the vector withheld |
| Cost and latency | 52,667 input + 24,572 output tokens, about $0.0623; median 9.5 s per call |

| Severity | Precision | Recall | Predicted |
|---|---|---|---|
| Critical | 45% | 56% | 11 |
| High | 38% | 33% | 8 |
| Medium | 40% | 22% | 5 |
| Low | n/a | 0% | 0 |

What the numbers say:

- **The model over-scores.** Of the 36 raw vectors, 19 score higher than NVD's and 1 lower; on average the raw base score is 1.31 points above NVD's. It never predicted Low. It defaults to the worst case on impact (C and I agree with NVD only 64% of the time), which is the part of a vector that short descriptions leave implicit.
- **The evidence rule does not find the bad vectors.** Withholding mostly-guessed vectors leaves accuracy flat (42% published vs 44% raw), and the raw vectors it withheld were right 50% of the time. A quote can exist in the report and still not support the metric it is attached to; the model often cites the same sentence for four or more metrics. Substring verification catches invented text, not weak reasoning.
- **Confidence carries some signal, on very few items.** Severity was right on 4 of 4 medium-confidence items and 19% of the 32 low-confidence ones.
- **CWE mostly comes back `unknown`.** The v2 prompt forbade outside knowledge and required evidence for every claim, and the model read that as "do not name a CWE unless the text names it". NVD analysts map CWEs from expertise, not quotes.
- **Report detection works.** The one miss was a vague second-hand warning ("a friend in IT said your servers might be vulnerable") that is arguably not a report.

The labels set a ceiling. NVD analysts score with knowledge the description does not contain (how the product is deployed, whether a login is needed), so "agreement with NVD" is not the same as "correct from the text". Thirty-six items also means each severity class has 9 examples; one item moves a class's recall by 11 points.

### v3 (current code): dev-split findings, test run pending

v3 is the CWE, CVSS-guidance, and quote-reuse changes described under [Design choices](#design-choices). It has not been run on the test split yet: the account allows 50 requests per model per day, and `gpt-5-mini`'s were used up by the v2 run. For the same reason the dev iteration ran on `gpt-5-nano` as a stand-in, which is a weak proxy. Dev split, 15 items, `python -m evals.compare evals/history/dev-v2-gpt-5-nano.json evals/history/dev-v3b-gpt-5-nano.json` (selected rows):

| Metric | v2 prompt | v3 prompt |
|---|---|---|
| CWE unknown | 100% | 67% |
| CWE exact | 0% | 17% |
| C / I / A agreement | 25% / 17% / 42% | 58% / 50% / 67% |
| Raw vectors over-scored / under-scored | 6 / 3 | 8 / 1 |
| Raw minus NVD base score, mean | +0.77 | +2.12 |
| Severity published (coverage) | 0% | 25% |
| Severity accuracy when published | n/a | 0% |

On `gpt-5-nano` at minimal reasoning, v3 named more CWEs and agreed more often on impact metrics, but over-scored more, not less. Reading the raw output explains part of it: nano wrote its own reasoning into the quote fields ("H – total loss (arbitrary code execution...") and scored a divide-by-zero as C:H/I:H/A:H despite the instructions. The guardrails caught this (most vectors withheld for unverified or overused quotes), but it means nano results say little about `gpt-5-mini`, which quoted the report correctly in v2. The before/after on the held-out split will be generated with `python -m evals.compare evals/history/v2-test-gpt-5-mini.json evals/results.json` once the test run is done.

## Limits

- Severity accuracy is far too low to use without review. The tool drafts; the analyst decides.
- Quote verification proves a quote exists, not that it supports the claim.
- The thin-report threshold (120 characters) is a blunt rule, and it was lowered after looking at the first eval run, so the eval is not independent of it.
- Small splits and one run per version. The v1 and v2 test runs differ in both schema and model (an account limit of 50 requests per model per day forced the switch), so they are not a model comparison. The v3 dev iteration ran on a different model than the test run will.
- NVD descriptions are cleaner than real inbound reports. The synthetic items are hand-written and few.
- Prompt injection inside a report is not handled beyond the schema constraint and the human gate.

## Ethics and safety

- **Assist, never replace.** Every result is a draft until an analyst approves it, and the log records who changed what. Severity drives patch SLAs and customer notifications; that decision stays with a person.
- **No internal data.** The eval uses only public NVD records and synthetic text written for this repo. Nothing from any employer or customer is in the data, prompts, or logs.
- **Dual use.** The tool reads reports and summarizes them; it does not write exploits or search for vulnerabilities. Run on private reports, it sends their text to a third-party API, so check your disclosure agreements and data-handling rules before pointing it at a real inbox.

## Run it

Requires Python 3.12+.

```bash
git clone https://github.com/LorenzoAPB/vuln-triage && cd vuln-triage
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

make test          # pytest, API mocked, no network
make eval          # replay the recorded eval responses; free and deterministic

export OPENAI_API_KEY=...   # only needed for new reports
vuln-triage triage examples/cve-2021-44228.txt --out triaged.json
python -m evals.run --split dev    # live, for items without a recording; iterate here
python -m evals.run --split test   # live, held out: once per finished version
```

`--model` selects another model; add its prices to `PRICES_PER_MTOK` first. Logs go to `logs/triage.jsonl`.

CI runs ruff, the test suite, and `python -m evals.run --split dev --offline --check` (plus the same for the test split once it has results for the current version), which replays the recorded responses and fails if the metrics differ from the committed results. A one-call live smoke test runs only if the repository has an `OPENAI_API_KEY` secret.

## License

[MIT](LICENSE)
