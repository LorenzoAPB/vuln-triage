"""Command-line review loop: the model drafts, a human decides, and every run is logged."""

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from cvss.exceptions import CVSS3MalformedError

from vuln_triage.guardrails import finalize, proposed_vector, score_vector
from vuln_triage.schema import ModelTriage, TriageResult
from vuln_triage.triage import MODEL, TriageError, call_model

LOG_PATH = Path("logs/triage.jsonl")
SEVERITIES = ["Critical", "High", "Medium", "Low", "None"]
EDITABLE = {"cwe": "cwe", "vector": "cvss_v31_vector", "severity": "severity", "product": "affected_product"}


def render(result: TriageResult, proposal: ModelTriage) -> str:
    if result.cvss_score is not None:
        cvss = f"{result.cvss_v31_vector}  ->  {result.cvss_score} {result.severity}"
    elif result.is_vulnerability_report:
        cvss = f"withheld, not enough evidence (model guess: {proposed_vector(proposal)})"
    else:
        cvss = "unknown"
    lines = [
        f"Report?     {'yes' if result.is_vulnerability_report else 'NO'}",
        f"Summary     {result.summary}",
        f"Product     {result.affected_product}",
        f"CWE         {result.cwe}",
        f"CVSS 3.1    {cvss}",
        f"No evidence {', '.join(result.guessed_metrics) or '-'}",
        f"Confidence  {result.confidence}",
        f"Flags       {', '.join(result.flags) or '-'}",
        f"Next step   {result.recommended_next_step}",
        "Evidence",
        *[f'  - {q.claim}: "{q.quote}"' for q in result.evidence_quotes],
    ]
    return "\n".join(lines)


def edit(result: TriageResult, field: str, value: str) -> TriageResult:
    """Apply one human edit. Raises ValueError if the value is invalid."""
    value = value.strip()
    if field == "cwe":
        if not re.fullmatch(r"CWE-\d+|unknown", value):
            raise ValueError("CWE must look like CWE-79, or be 'unknown'")
        return result.model_copy(update={"cwe": value})
    if field == "vector":
        if value == "unknown":
            return result.model_copy(update={"cvss_v31_vector": value, "cvss_score": None, "severity": "unknown"})
        if not value.startswith("CVSS:3.1/"):
            raise ValueError("vector must start with CVSS:3.1/")
        try:
            score, severity = score_vector(value)
        except CVSS3MalformedError as e:
            raise ValueError(str(e)) from e
        return result.model_copy(
            update={"cvss_v31_vector": value, "cvss_score": score, "severity": severity, "guessed_metrics": []}
        )
    if field == "severity":
        if value not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        return result.model_copy(update={"severity": value})
    if field == "product":
        return result.model_copy(update={"affected_product": value})
    raise ValueError(f"field must be one of {', '.join(EDITABLE)}")


def overrides(draft: TriageResult, final: TriageResult) -> dict[str, dict]:
    """Every field the human changed, with the model's value and the human's value."""
    before, after = draft.model_dump(), final.model_dump()
    return {k: {"model": before[k], "human": after[k]} for k in before if before[k] != after[k]}


def review(draft: TriageResult, proposal: ModelTriage) -> tuple[str, TriageResult, str | None]:
    """Ask the human to approve, edit, or reject. Returns (decision, final result, reject reason)."""
    result = draft
    while True:
        choice = input("\n[a]pprove  [e]dit  [r]eject > ").strip().lower()
        if choice == "a":
            return "approved", result, None
        if choice == "r":
            return "rejected", result, input("Reason > ").strip() or None
        if choice == "e":
            field = input(f"Field ({', '.join(EDITABLE)}) > ").strip().lower()
            try:
                result = edit(result, field, input("New value > "))
            except ValueError as e:
                print(f"  not changed: {e}")
                continue
            print("\n" + render(result, proposal))


def log_event(record: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(record) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vuln-triage", description="LLM-drafted, human-approved triage.")
    commands = parser.add_subparsers(dest="command", required=True)
    triage_cmd = commands.add_parser("triage", help="Draft a triage for one report and review it.")
    triage_cmd.add_argument("file", type=Path, help="Text file containing the vulnerability report.")
    triage_cmd.add_argument("--model", default=MODEL)
    triage_cmd.add_argument("--out", type=Path, help="Write the approved result here as JSON.")
    args = parser.parse_args(argv)

    report = args.file.read_text()
    base = {
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        "file": str(args.file),
        "report_sha256": hashlib.sha256(report.encode()).hexdigest(),
        "model": args.model,
    }
    try:
        proposal, usage = call_model(report, args.model)
    except TriageError as e:
        log_event({**base, "event": "parse_failure", "error": str(e)})
        print(f"error: model output rejected: {e}", file=sys.stderr)
        return 2

    draft = finalize(proposal, report)
    print(render(draft, proposal))
    try:
        decision, final, reason = review(draft, proposal)
    except (EOFError, KeyboardInterrupt):
        decision, final, reason = "abandoned", draft, None

    log_event(
        {
            **base,
            "event": "triage",
            "cached": usage.cached,
            "latency_s": usage.latency_s,
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cost_usd": round(usage.cost_usd, 6),
            "flags": draft.flags,
            "confidence": draft.confidence,
            "decision": decision,
            "reject_reason": reason,
            "overrides": overrides(draft, final),
            "final": final.model_dump() if decision == "approved" else None,
        }
    )
    print(f"\n{decision.capitalize()}. Logged to {LOG_PATH}")
    if decision == "approved" and args.out:
        args.out.write_text(final.model_dump_json(indent=2) + "\n")
        print(f"Saved to {args.out}")
    return 0
