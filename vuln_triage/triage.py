"""One structured-output call: report text in, ModelTriage out."""

import hashlib
import json
import sys
from pathlib import Path

from openai import OpenAI

from vuln_triage.schema import ModelTriage

MODEL = "gpt-4.1-mini"
CACHE_DIR = Path(".cache")

SYSTEM_PROMPT = """You are a PSIRT analyst triaging a security vulnerability report.
Rules:
- Use only facts stated in the report. Do not use outside knowledge about the product or CVE.
- If the report does not support a field, answer 'unknown'.
- Every claim you make needs an evidence quote copied exactly from the report.
- Set confidence to 'low' when the report is short, vague, or missing key details.
- If the text is not a vulnerability report, set is_vulnerability_report to false."""


def triage(report: str, model: str = MODEL) -> ModelTriage:
    key = hashlib.sha256(f"{model}\n{SYSTEM_PROMPT}\n{report}".encode()).hexdigest()
    cached = CACHE_DIR / f"{key}.json"
    if cached.exists():
        return ModelTriage.model_validate_json(cached.read_text())

    response = OpenAI().responses.parse(
        model=model,
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": report},
        ],
        text_format=ModelTriage,
        temperature=0,
    )
    result = response.output_parsed
    print(f"[{model}] tokens in={response.usage.input_tokens} out={response.usage.output_tokens}", file=sys.stderr)

    CACHE_DIR.mkdir(exist_ok=True)
    cached.write_text(result.model_dump_json())
    return result


if __name__ == "__main__":
    report_text = Path(sys.argv[1]).read_text()
    print(json.dumps(triage(report_text).model_dump(), indent=2))
