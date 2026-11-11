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

MODEL = "gpt-4.1-mini"
CACHE_DIR = Path(os.environ.get("VULN_TRIAGE_CACHE", ".cache"))

# USD per 1M tokens (input, output). Source: https://platform.openai.com/docs/models/gpt-4.1-mini
# Checked 2026-11-11. Cached-input discounts are ignored, so estimates err high.
PRICES_PER_MTOK = {
    "gpt-4.1-mini": (0.40, 1.60),
}

SYSTEM_PROMPT = """You are a PSIRT analyst triaging a security vulnerability report.
Rules:
- Use only facts stated in the report. Do not use outside knowledge about the product or CVE.
- If the report does not support a field, answer 'unknown'.
- CVSS: propose a value for every base metric. Give an exact supporting quote when the report
  supports the value; use '' as the quote when you are inferring. Use 'unknown' only when you
  cannot make a reasonable estimate.
- Every claim you make needs an evidence quote copied exactly from the report.
- Set confidence to 'low' when the report is short, vague, or missing key details.
- If the text is not a vulnerability report, set is_vulnerability_report to false."""


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
    latency_s: float
    cached: bool

    @property
    def cost_usd(self) -> float:
        price_in, price_out = PRICES_PER_MTOK[self.model]
        return (self.input_tokens * price_in + self.output_tokens * price_out) / 1_000_000


def cache_key(report: str, model: str) -> str:
    schema = json.dumps(ModelTriage.model_json_schema(), sort_keys=True)
    return hashlib.sha256(f"{model}\n{SYSTEM_PROMPT}\n{schema}\n{report}".encode()).hexdigest()


def call_model(
    report: str,
    model: str = MODEL,
    cache_dir: Path = CACHE_DIR,
    offline: bool = False,
) -> tuple[ModelTriage, Usage]:
    path = cache_dir / f"{cache_key(report, model)}.json"
    if path.exists():
        record = json.loads(path.read_text())
        return ModelTriage.model_validate(record["proposal"]), Usage(**record["usage"], model=model, cached=True)
    if offline:
        raise CacheMiss(f"no cached response for this report in {cache_dir}")

    start = time.perf_counter()
    try:
        response = OpenAI().responses.parse(
            model=model,
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": report},
            ],
            text_format=ModelTriage,
            temperature=0,
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
