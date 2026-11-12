"""Record model responses for an eval split through the OpenAI Batch API, then replay them with evals.run.

The Batch API bills half price and has its own limits, separate from the 50-requests-per-day limit
that stalled earlier runs. Requests are identical to live calls (same body, same cache key), so the
recordings are interchangeable; only latency is missing.

  python -m evals.batch --split dev --model gpt-4o-mini --prompt v4
  python -m evals.run --split dev --model gpt-4o-mini --prompt v4 --offline
"""

import argparse
import json
import sys
import time
from pathlib import Path

from openai import OpenAI
from openai.lib._parsing._responses import type_to_text_format_param  # what responses.parse sends

from evals.run import RESULTS, load_split
from vuln_triage.schema import ModelTriage
from vuln_triage.triage import MODEL, PROMPT_VERSION, PROMPTS, cache_key, request_body, user_message

HERE = Path(__file__).parent
RECORDINGS = HERE / "recordings"


def output_text(body: dict) -> str | None:
    return next(
        (
            c["text"]
            for o in body["output"]
            if o["type"] == "message"
            for c in o["content"]
            if c["type"] == "output_text"
        ),
        None,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--split", choices=RESULTS, required=True)
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--prompt", choices=PROMPTS, default=PROMPT_VERSION)
    args = parser.parse_args()
    prompt = PROMPTS[args.prompt]

    items = load_split(args.split)
    pending: dict[str, str] = {}  # cache key -> user message, for items without a recording
    for item in items:
        content = user_message(item["text"], prompt)
        key = cache_key(content, args.model, prompt)
        if not (RECORDINGS / f"{key}.json").exists():
            pending[key] = content
    if not pending:
        print("all items already recorded", file=sys.stderr)
        return 0

    text_format = type_to_text_format_param(ModelTriage)
    lines = [
        json.dumps(
            {
                "custom_id": key,
                "method": "POST",
                "url": "/v1/responses",
                "body": {**request_body(content, args.model, prompt), "text": {"format": text_format}},
            }
        )
        for key, content in pending.items()
    ]
    client = OpenAI(timeout=60)
    upload = client.files.create(file=("batch.jsonl", "\n".join(lines).encode()), purpose="batch")
    batch = client.batches.create(input_file_id=upload.id, endpoint="/v1/responses", completion_window="24h")
    print(f"submitted {batch.id}: {len(pending)} requests", file=sys.stderr)
    while batch.status not in ("completed", "failed", "expired", "cancelled"):
        time.sleep(30)
        batch = client.batches.retrieve(batch.id)
        print(f"{batch.status} {batch.request_counts}", file=sys.stderr)
    if batch.status != "completed" or not batch.output_file_id:
        print(f"batch {batch.status}: {batch.errors}", file=sys.stderr)
        return 1

    written = 0
    for line in client.files.content(batch.output_file_id).text.splitlines():
        result = json.loads(line)
        body = result["response"]["body"] if result.get("response") else None
        text = output_text(body) if body and body.get("status") == "completed" else None
        if text is None:  # failures are reported, never recorded, like live calls
            print(f"no output for {result['custom_id'][:12]}: {result.get('error') or body}", file=sys.stderr)
            continue
        usage = {
            "input_tokens": body["usage"]["input_tokens"],
            "output_tokens": body["usage"]["output_tokens"],
            "latency_s": None,
            "batch": True,
        }
        proposal = ModelTriage.model_validate_json(text)
        record = {"proposal": proposal.model_dump(), "usage": usage}
        (RECORDINGS / f"{result['custom_id']}.json").write_text(json.dumps(record, indent=2) + "\n")
        written += 1
    print(f"recorded {written} of {len(pending)} responses", file=sys.stderr)
    return 0 if written == len(pending) else 1


if __name__ == "__main__":
    raise SystemExit(main())
