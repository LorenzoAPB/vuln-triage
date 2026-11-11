"""One structured-output call: report text in, ModelTriage out, with a disk cache and usage stats."""

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from openai import ContentFilterFinishReasonError, LengthFinishReasonError, OpenAI
from pydantic import ValidationError

from vuln_triage.schema import ModelTriage

MODEL = "gpt-5-mini"
CACHE_DIR = Path(os.environ.get("VULN_TRIAGE_CACHE", ".cache"))

# USD per 1M tokens (input, output), from https://platform.openai.com/docs/models/<model>
# Checked 2026-11-11. Cached-input discounts are ignored, so estimates err high.
PRICES_PER_MTOK = {
    "gpt-5-mini": (0.25, 2.00),
    "gpt-5-nano": (0.05, 0.40),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-5.4-nano": (0.20, 1.25),
    "gpt-5.4-mini": (0.75, 4.50),
    "gpt-4.1-mini": (0.40, 1.60),
}

# Reasoning models reject `temperature`; the lowest reasoning effort for gpt-5-mini/nano is "minimal".
REQUEST_OPTIONS: dict[str, dict] = {
    "gpt-5-mini": {"reasoning": {"effort": "minimal"}},
    "gpt-5-nano": {"reasoning": {"effort": "minimal"}},
    "gpt-4o-mini": {"temperature": 0},
    "gpt-5.4-mini": {"temperature": 0},
    "gpt-5.4-nano": {"temperature": 0},
    "gpt-4.1-mini": {"temperature": 0},
}

REQUEST_TIMEOUT_S = 90  # fail a hung request instead of waiting the SDK default of 10 minutes

V3_SYSTEM_PROMPT = """You are a PSIRT analyst triaging a security vulnerability report.
Rules:
- Facts about the product (versions, deployment, exploitation) come only from the report. Use your
  knowledge of CWE and CVSS only to classify what the report describes.
- If the report does not support a field, answer 'unknown'.
- CWE: give the most specific CWE an NVD analyst would assign to the weakness described (for
  example CWE-79 rather than CWE-74), and copy the text that describes the weakness into cwe_quote.
  Use 'unknown' only when the report does not describe the weakness.
- CVSS v3.1: propose every base metric and quote the exact report text supporting it, or use ''
  when you are inferring. Score what the report states, not the worst case:
  - C, I, A: H only for total loss (arbitrary code execution, full read or write access, the whole
    service crashing); L for limited or partial impact; N when that impact is not described.
    A crash or resource exhaustion affects A only: C and I stay N unless the report describes
    reading or changing data.
  - PR: N when the report says or clearly implies no account is needed; L for an ordinary user;
    H for an administrator.
  - UI: R when a victim must click, open, or visit something; otherwise N.
  - AV: N for attacks over the network, A for an adjacent network, L for local access or a
    malicious file the victim opens, P for physical access.
  - AC: L unless the report names a condition outside the attacker's control.
  - S: C only when the impact crosses a security boundary (script running in a victim's browser,
    escape from a sandbox or VM); otherwise U.
  Use a different quote for each metric where you can. One quote may support at most three metrics.
- Every claim you make needs an evidence quote copied exactly from the report.
- A quote (in evidence_quotes, cwe_quote, or a CVSS metric) is text copied character for character
  from the report, never your own explanation. If no report text fits, the quote is ''.
- Set confidence to 'low' when the report is short, vague, or missing key details.
- If the text is not a vulnerability report, set is_vulnerability_report to false."""

KNN_SYSTEM_PROMPT = (  # used by the exp-knn experiments, not by the default version
    V3_SYSTEM_PROMPT
    + """
- After the report you get similar past CVEs with the CWE and CVSS vector NVD analysts assigned.
  They are not about this report: never quote them. Use them to calibrate how NVD classifies and
  scores this kind of weakness, especially for metrics the report leaves implicit (leave those
  quotes ''). Prefer the report's own statements when they disagree with the examples."""
)


@dataclass(frozen=True)
class Prompt:
    """A prompt version: system prompt, retrieved examples, and how guardrails treat inferred metrics."""

    version: str
    system: str
    neighbours: int  # similar NVD CVEs appended to the report; 0 means none
    publish_inferred: bool  # False: withhold mostly-inferred vectors (v3). True: publish as provisional (v4).
    effort: str = "minimal"  # reasoning effort, for reasoning models only (gpt-5-mini, gpt-5-nano)


PROMPTS = {  # every version with recorded results stays here, so CI can replay it
    "v3": Prompt("v3", V3_SYSTEM_PROMPT, neighbours=0, publish_inferred=False),
    # v4 = v3's prompt with the provisional-publishing rule: it won on the dev split (evals/ablation.md).
    "v4": Prompt("v4", V3_SYSTEM_PROMPT, neighbours=0, publish_inferred=True),
    # Dev-split experiments that did not beat v4; kept so the ablation table replays.
    "exp-knn": Prompt("exp-knn", KNN_SYSTEM_PROMPT, neighbours=5, publish_inferred=True),
    "exp-low": Prompt("exp-low", V3_SYSTEM_PROMPT, neighbours=0, publish_inferred=True, effort="low"),
    "exp-knn-low": Prompt("exp-knn-low", KNN_SYSTEM_PROMPT, neighbours=5, publish_inferred=True, effort="low"),
}
PROMPT_VERSION = "v4"  # the default; results files record the version that produced them


class TriageError(Exception):
    """The model call did not produce a valid ModelTriage (refusal, truncation, schema mismatch)."""


class CacheMiss(Exception):
    """Offline mode was requested and the response is not in the cache."""


@dataclass
class Usage:
    """Usage of the API call that produced a result. On a cache hit these are the recorded
    numbers from the original call, and `cached` is True: nothing was spent this time."""

    model: str
    input_tokens: int
    output_tokens: int
    latency_s: float | None  # None for Batch API calls, which have no per-request latency
    cached: bool
    batch: bool = False  # the Batch API bills half price

    @property
    def cost_usd(self) -> float:
        price_in, price_out = PRICES_PER_MTOK[self.model]
        full = (self.input_tokens * price_in + self.output_tokens * price_out) / 1_000_000
        return full / 2 if self.batch else full


def user_message(report: str, prompt: Prompt) -> str:
    """The report, followed by its nearest NVD neighbours when the prompt version uses them."""
    if not prompt.neighbours:
        return report
    from vuln_triage.retrieval import pool_index  # loads the pool only when a prompt needs it

    examples = "\n\n".join(
        f"Example {i}: {d['text'][:600]}\nNVD: {d['cwe']}, {d['vector']}"
        for i, d in enumerate(pool_index().nearest(report, prompt.neighbours), 1)
    )
    return f"REPORT:\n{report}\n\nSIMILAR PAST CVES (not this report; never quote):\n{examples}"


def cache_key(user_content: str, model: str, prompt: Prompt) -> str:
    schema = json.dumps(ModelTriage.model_json_schema(), sort_keys=True)
    effort = f"\neffort={prompt.effort}" if prompt.effort != "minimal" else ""  # keeps pre-v4 keys unchanged
    return hashlib.sha256(f"{model}\n{prompt.system}\n{schema}\n{user_content}{effort}".encode()).hexdigest()


def request_body(user_content: str, model: str, prompt: Prompt) -> dict:
    """Responses API arguments, shared by live calls and Batch API requests."""
    options = REQUEST_OPTIONS.get(model, {})
    if "reasoning" in options:
        options = {"reasoning": {"effort": prompt.effort}}
    return {
        "model": model,
        "input": [{"role": "system", "content": prompt.system}, {"role": "user", "content": user_content}],
        **options,
    }


def call_model(
    report: str,
    model: str = MODEL,
    cache_dir: Path = CACHE_DIR,
    offline: bool = False,
    prompt: Prompt = PROMPTS[PROMPT_VERSION],
) -> tuple[ModelTriage, Usage]:
    content = user_message(report, prompt)
    path = cache_dir / f"{cache_key(content, model, prompt)}.json"
    if path.exists():
        record = json.loads(path.read_text())
        return ModelTriage.model_validate(record["proposal"]), Usage(**record["usage"], model=model, cached=True)
    if offline:
        raise CacheMiss(f"no cached response for this report in {cache_dir}")

    start = time.perf_counter()
    try:
        response = OpenAI(timeout=REQUEST_TIMEOUT_S, max_retries=1).responses.parse(
            **request_body(content, model, prompt), text_format=ModelTriage
        )
    except (ValidationError, LengthFinishReasonError, ContentFilterFinishReasonError) as e:
        raise TriageError(f"{type(e).__name__}: {e}") from e
    latency = round(time.perf_counter() - start, 3)
    if response.output_parsed is None:
        raise TriageError(f"no parsed output (status={response.status})")

    usage = {
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "latency_s": latency,
    }
    cache_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"proposal": response.output_parsed.model_dump(), "usage": usage}, indent=2) + "\n")
    return response.output_parsed, Usage(**usage, model=model, cached=False)
