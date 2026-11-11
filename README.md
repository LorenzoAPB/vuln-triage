# vuln-triage

[![CI](https://github.com/LorenzoAPB/vuln-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/LorenzoAPB/vuln-triage/actions/workflows/ci.yml)

An LLM drafts the triage of a security vulnerability report, code checks every claim it can, and a human approves, edits, or rejects the draft. Nothing is final until a person decides.

![Demo: the guardrails withhold the model's 7.5 High guess for an ArubaOS report; the analyst sets the vector to 2.4 Low, then rejects a two-line XSS report](docs/demo.gif)

<sub>Replays recorded `gpt-4o-mini` responses from the v3 held-out run (`vuln-triage triage --model gpt-4o-mini`, cache `evals/recordings`), so it makes no API calls. The CLI default model is `gpt-5-mini`; see [Results](#results).</sub>

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

**Per-metric evidence.** Each metric comes with the exact report text that supports it, or `''` when the model is inferring. Code checks every quote against the report (case- and whitespace-insensitive substring match). A metric counts as guessed if its quote is missing, is not in the report, or is the same sentence cited for more than three metrics (one sentence cannot carry most of a vector; the v2 test run on `gpt-5-mini` found the model doing exactly that). One guess caps confidence at medium. More than four guesses, or a report under 120 characters, and the vector is withheld: the analyst sees the model's guess, labeled as a guess, but no score is published.

**Score what the report states, not the worst case.** The prompt spells out standard CVSS v3.1 practice: C/I/A are High only for total loss, a crash affects availability only, PR:N needs the report to say or clearly imply no account, S:C needs a crossed security boundary. This targets the over-scoring measured in the v2 test run on `gpt-5-mini`.

**Every claim cites the report.** Evidence quotes that do not appear in the report are dropped and flagged (`dropped_N_unverified_quotes`). No verified evidence at all means low confidence.

**CWE is classification, so the model may use its CWE knowledge.** Facts about the product come only from the report, but mapping "a missing buffer size check" to CWE-787 is classification, which is what an NVD analyst does. The model gives the most specific CWE plus a `cwe_quote` describing the weakness; if that quote is not in the report, code resets the CWE to `unknown` (`cwe_without_evidence`). In the v2 test run on `gpt-5-mini`, forbidding outside knowledge made the model answer `unknown` for 75% of CWEs.

**`unknown` is a legal answer, except for CVSS metrics.** Strict schemas make every field required, so without an explicit `unknown` the model is pushed to invent a CWE or a product. CVSS metrics are the exception, for a reason found in the eval: when each metric could be `unknown`, the model left at least one unknown on every NVD item, so no severity was ever produced ([first run: v1 schema, `gpt-5.4-nano`](evals/history/v1-test-gpt-5.4-nano.md)). Now the model always proposes, and code decides from the evidence whether to publish.

**Three confidence levels, not a percentage.** "0.87" invites false precision. Low, medium, and high are levels a reviewer can check, and code can lower them (never raise them) based on what it verified.

**Non-reports are refused.** `is_vulnerability_report: false` short-circuits to an empty draft with "route back to sender" as the next step, instead of a CVSS score for an offsite reminder.

**Human in the loop, with a record.** The analyst can edit the CWE, the vector (the score and severity are recomputed), the severity, and the product, or reject with a reason. Each run logs model, latency, tokens, estimated cost, guardrail flags, the decision, and every field the human changed with the model's value next to theirs. Those overrides are the data you would use to improve the prompt.

**Cheap model, cached calls.** The CLI defaults to `gpt-5-mini` at minimal reasoning effort (`MODEL` in [`triage.py`](vuln_triage/triage.py)); the v2 test run on it cost $0.0623 for 48 reports. The current held-out results were produced by a different model, `gpt-4o-mini` (see [Results](#results)). Responses are cached on disk, keyed by model, prompt, schema, and report text, so re-runs are free and the eval replays exactly. Prices live in one constant (`PRICES_PER_MTOK`) with the source URL and the date they were checked.

## Evaluation method

Two splits, both built by the same fixed rule in [`build_dataset.py`](evals/build_dataset.py) (NVD records where NVD itself assigned the CVSS 3.1 vector and a specific CWE, 150-900 character descriptions, no SAP, first N per severity with distinct CWEs) from different publication windows:

| Split | Items | Window | Used for |
|---|---|---|---|
| dev | 12 NVD (3 per severity) + 3 synthetic | June-July 2023 | All prompt and guardrail iteration |
| test | 36 NVD (9 per severity) + 12 synthetic | March-April 2023 | Held out; run once per finished version |

Labels are NVD's CVSS 3.1 vector and primary CWE. The lenient CWE metric counts a direct parent or child in MITRE's Research view (CWE-1000, from [`cwe_parents.json`](evals/cwe_parents.json), built by [`build_cwe_tree.py`](evals/build_cwe_tree.py)). Every number below is generated by `python -m evals.run` or `python -m evals.compare`; snapshots of each run are in [`evals/history`](evals/history).

## Results

Every table below names the model and the prompt/schema version that produced it. The two held-out runs used different models, so they are **not a controlled comparison**: a difference between them could come from the prompt or from the model.

### Current held-out numbers: v3 prompt, `gpt-4o-mini`, held-out test, run once 2026-11-11

Test split, 48 items, 0 parse failures, copied from [`evals/results.md`](evals/results.md) (snapshot: [`evals/history/v3-test-gpt-4o-mini.md`](evals/history/v3-test-gpt-4o-mini.md)). This run used `gpt-4o-mini`, not the CLI default `gpt-5-mini`, because `gpt-5-mini`'s 50-requests-per-day quota was used up; `gpt-4o-mini` was the cheapest model with structured outputs and enough quota left. It has no earlier run, so there is no same-model before/after.

| What | Result |
|---|---|
| Report vs noise: report precision / recall | 100% / 98% (42 reports) |
| Report vs noise: noise precision / recall | 86% / 100% (6 non-reports) |
| Severity published (vector passed the guardrails) | 8% of NVD items |
| Severity accuracy when published | 67% |
| Severity accuracy of the raw model vector, no guardrails | 42% (13 over-scored, 8 under-scored) |
| Raw minus NVD base score | mean +0.21, mean absolute 1.56 |
| CWE exact match with NVD primary CWE | 36% (36% answered `unknown`) |
| CWE exact or direct parent/child (lenient) | 39% |
| CVSS vector exact match, published / raw model vector | 0% / 14% |
| Per-metric agreement AV / AC / PR / UI / S / C / I / A | 81% / 89% / 78% / 86% / 94% / 69% / 33% / 64% |
| Thin and vague reports (6) | 6 low confidence, 6 with the vector withheld |
| Cost and latency | 70,763 input + 13,814 output tokens, about $0.0189; median 5.07 s per call |

| Severity (published) | Precision | Recall | Predicted |
|---|---|---|---|
| Critical | 100% | 22% | 2 |
| High | n/a | 0% | 0 |
| Medium | 0% | 0% | 1 |
| Low | n/a | 0% | 0 |

What the numbers say (about v3 on `gpt-4o-mini` only):

- **The guardrails withheld almost every vector.** `gpt-4o-mini` left most per-metric quotes empty, which the schema defines as "inferring", so 33 of 36 NVD items were flagged `cvss_mostly_guessed`. Only 3 severities were published; 67% accuracy on 3 items says almost nothing.
- **The raw vector is more balanced but no more accurate.** 42% raw severity accuracy with 13 over- and 8 under-scored, mean bias +0.21. Integrity is the weak metric (33% agreement).
- **CWE is answered more often.** 36% exact, 39% lenient, 36% `unknown`. Several remaining `unknown`s come from `cwe_without_evidence`: the CWE quote was not in the report.
- **Report detection:** the one miss was again the vague second-hand warning ("a friend in IT said your servers might be vulnerable").

### Earlier held-out run: v2 prompt, `gpt-5-mini` (not a controlled comparison)

Test split, 48 items, 0 parse failures, from [`evals/history/v2-test-gpt-5-mini.md`](evals/history/v2-test-gpt-5-mini.md). Different prompt **and** different model from the run above, so do not read the differences as the effect of v3.

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

What v2 on `gpt-5-mini` showed, and what v3 was built to fix: it over-scored (raw score 1.31 points above NVD's on average, never predicted Low), cited the same sentence for four or more metrics, and answered `unknown` for 75% of CWEs because the v2 prompt forbade outside knowledge.

The labels set a ceiling for both runs. NVD analysts score with knowledge the description does not contain (how the product is deployed, whether a login is needed), so "agreement with NVD" is not the same as "correct from the text". Thirty-six NVD items means 9 per severity class; one item moves a class's recall by 11 points.

### Pending: the fair comparison

The controlled comparison is v3 on `gpt-5-mini` over the same 48 test items, against the v2 `gpt-5-mini` run, once the daily quota allows: `python -m evals.run --split test --model gpt-5-mini`, then `python -m evals.compare evals/history/v2-test-gpt-5-mini.json evals/results.json`. The prompt will not change before that run.

### v3 dev-split findings (`gpt-5-nano` as a stand-in)

The v3 changes were developed on the dev split only, on `gpt-5-nano` (quota again), which is a weak proxy. Dev split, 15 items, `python -m evals.compare evals/history/dev-v2-gpt-5-nano.json evals/history/dev-v3b-gpt-5-nano.json` (selected rows; both columns `gpt-5-nano`):

| Metric | v2 prompt, `gpt-5-nano` | v3 prompt, `gpt-5-nano` |
|---|---|---|
| CWE unknown | 100% | 67% |
| CWE exact | 0% | 17% |
| C / I / A agreement | 25% / 17% / 42% | 58% / 50% / 67% |
| Raw vectors over-scored / under-scored | 6 / 3 | 8 / 1 |
| Raw minus NVD base score, mean | +0.77 | +2.12 |
| Severity published (coverage) | 0% | 25% |
| Severity accuracy when published | n/a | 0% |

On `gpt-5-nano` at minimal reasoning, v3 named more CWEs and agreed more often on impact metrics, but over-scored more, not less. Nano wrote its own reasoning into the quote fields ("H – total loss (arbitrary code execution...") and scored a divide-by-zero as C:H/I:H/A:H despite the instructions; the guardrails withheld most of those vectors.

## Limits

- Severity accuracy is far too low to use without review. The tool drafts; the analyst decides.
- Quote verification proves a quote exists, not that it supports the claim.
- The thin-report threshold (120 characters) is a blunt rule, and it was lowered after looking at the first eval run, so the eval is not independent of it.
- Small splits and one run per version. The v1 (`gpt-5.4-nano`), v2 (`gpt-5-mini`), and v3 (`gpt-4o-mini`) test runs each used a different model (an account limit of 50 requests per model per day forced the switches), so no two of them are a controlled comparison. The v3 dev iteration ran on `gpt-5-nano`.
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

The default model is `gpt-5-mini` (`vuln-triage triage --help` shows it); `--model` selects another, for example `--model gpt-4o-mini` to replay the v3 eval recordings. Add a new model's prices to `PRICES_PER_MTOK` first. Logs go to `logs/triage.jsonl`.

CI runs ruff, the test suite, and `python -m evals.run --split dev --offline --check` (and the same for the test split), which replays the recorded responses and fails if the metrics differ from the committed results. A one-call live smoke test runs only if the repository has an `OPENAI_API_KEY` secret.

## License

[MIT](LICENSE)
