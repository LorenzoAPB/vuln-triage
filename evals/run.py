"""Run an eval split through the real pipeline and write its results.

The dev split (evals/dev.jsonl) is for prompt and guardrail iteration. The test split
(evals/test.jsonl) is held out and only run on a finished version.

  python -m evals.run --split dev          # call the API only for items not yet recorded
  python -m evals.run --split test --offline --check   # replay recordings; fail if metrics changed (CI)
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from evals.metrics import SEVERITIES, confusion, cwe_related, metric_agreement, precision_recall
from vuln_triage.guardrails import METRIC_ORDER, finalize, proposed_vector, score_vector
from vuln_triage.triage import MODEL, PROMPT_VERSION, PROMPTS, Prompt, TriageError, call_model

HERE = Path(__file__).parent
RECORDINGS = HERE / "recordings"
PRED_SEVERITIES = [*SEVERITIES, "None", "unknown"]
RESULTS = {"test": "results", "dev": "dev_results"}  # file stem per split
CWE_PARENTS = json.loads((HERE / "cwe_parents.json").read_text())["parents"]


def run_item(item: dict, model: str, offline: bool, prompt: Prompt) -> tuple[dict, bool]:
    """One eval row, and whether it took a live API call (failures are never cached)."""
    row = {k: item.get(k) for k in ["id", "kind", "is_report", "severity", "cwe", "cwe_all", "vector"]}
    try:
        proposal, usage = call_model(item["text"], model, RECORDINGS, offline, prompt)
    except TriageError as e:
        return {**row, "parse_failure": str(e)}, True
    result = finalize(proposal, item["text"], prompt.publish_inferred)
    raw_vector = proposed_vector(proposal)
    return {
        **row,
        "parse_failure": None,
        "pred_is_report": result.is_vulnerability_report,
        "pred_severity": result.severity,
        "pred_cwe": result.cwe,
        "pred_vector": result.cvss_v31_vector,
        "raw_vector": raw_vector,
        "raw_severity": score_vector(raw_vector)[1] if result.is_vulnerability_report else "unknown",
        "raw_metrics": {m: getattr(proposal.cvss, m).value for m in METRIC_ORDER},
        "confidence": result.confidence,
        "flags": result.flags,
        "guessed_metrics": result.guessed_metrics,
        "usage": {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "latency_s": usage.latency_s,
            "cost_usd": usage.cost_usd,
        },
    }, not usage.cached


def rank(severity: str) -> int:
    """Order severities for over/under comparisons; 'unknown' ranks below 'None'."""
    return ["unknown", "None", "Low", "Medium", "High", "Critical"].index(severity)


def compute(rows: list[dict], model: str) -> dict:
    ok = [r for r in rows if not r["parse_failure"]]
    nvd = [r for r in ok if r["kind"] == "nvd"]
    unclear = [r for r in ok if r["kind"] in ("thin", "vague")]

    gold_report = ["report" if r["is_report"] else "noise" for r in ok]
    pred_report = ["report" if r["pred_is_report"] else "noise" for r in ok]

    gold_sev = [r["severity"] for r in nvd]
    published = [r for r in nvd if r["pred_vector"] != "unknown"]
    withheld = [r for r in nvd if r["pred_vector"] == "unknown"]
    scored = [r for r in nvd if r["raw_severity"] != "unknown"]
    score_diffs = [score_vector(r["raw_vector"])[0] - score_vector(r["vector"])[0] for r in scored]
    usages = [r["usage"] for r in ok]
    latencies = [u["latency_s"] for u in usages if u["latency_s"] is not None]  # None: Batch API

    return {
        "model": model,
        "items": len(rows),
        "parse_failures": len(rows) - len(ok),
        "report_detection": {
            "report": precision_recall(gold_report, pred_report, "report"),
            "noise": precision_recall(gold_report, pred_report, "noise"),
            "confusion": confusion(gold_report, pred_report),
        },
        "severity": {
            "n": len(nvd),
            "coverage": len(published) / len(nvd),
            "per_class": {s: precision_recall(gold_sev, [r["pred_severity"] for r in nvd], s) for s in SEVERITIES},
            "confusion": confusion(gold_sev, [r["pred_severity"] for r in nvd]),
            "accuracy_when_published": sum(r["pred_severity"] == r["severity"] for r in published) / len(published)
            if published
            else None,
            "accuracy_all": sum(r["pred_severity"] == r["severity"] for r in nvd) / len(nvd),  # withheld = miss
            "raw_accuracy": sum(r["raw_severity"] == r["severity"] for r in nvd) / len(nvd),
            "raw_confusion": confusion(gold_sev, [r["raw_severity"] for r in nvd]),
            "raw_over_scored": sum(rank(r["raw_severity"]) > rank(r["severity"]) for r in nvd),
            "raw_under_scored": sum(rank(r["raw_severity"]) < rank(r["severity"]) for r in nvd),
            "raw_score_bias": round(statistics.mean(score_diffs), 2),
            "raw_score_mae": round(statistics.mean(abs(d) for d in score_diffs), 2),
            "raw_accuracy_when_withheld": sum(r["raw_severity"] == r["severity"] for r in withheld) / len(withheld)
            if withheld
            else None,
        },
        "severity_accuracy_by_confidence": {
            c: {"n": len(group), "accuracy": sum(r["pred_severity"] == r["severity"] for r in group) / len(group)}
            for c in ["low", "medium", "high"]
            if (group := [r for r in nvd if r["confidence"] == c])
        },
        "cwe": {
            "exact": sum(r["pred_cwe"] == r["cwe"] for r in nvd) / len(nvd),
            "in_any_nvd_cwe": sum(r["pred_cwe"] in r["cwe_all"] for r in nvd) / len(nvd),
            "parent_or_child": sum(cwe_related(r["pred_cwe"], r["cwe"], CWE_PARENTS) for r in nvd) / len(nvd),
            "unknown": sum(r["pred_cwe"] == "unknown" for r in nvd) / len(nvd),
        },
        "cvss_vector": {
            "exact_published": sum(r["pred_vector"] == r["vector"] for r in nvd) / len(nvd),
            "exact_raw": sum(r["raw_vector"] == r["vector"] for r in nvd) / len(nvd),
            "per_metric_raw": metric_agreement([r["vector"] for r in nvd], [r["raw_metrics"] for r in nvd]),
        },
        "thin_and_vague": {
            "n": len(unclear),
            "detected_as_report": sum(r["pred_is_report"] for r in unclear),
            "low_confidence": sum(r["confidence"] == "low" for r in unclear),
            "vector_withheld": sum(r["pred_vector"] == "unknown" for r in unclear),
        },
        "cost": {
            "input_tokens": sum(u["input_tokens"] for u in usages),
            "output_tokens": sum(u["output_tokens"] for u in usages),
            "usd": round(sum(u["cost_usd"] for u in usages), 4),
            "latency_s_mean": round(statistics.mean(latencies), 2) if latencies else None,
            "latency_s_p50": round(statistics.median(latencies), 2) if latencies else None,
            "latency_s_max": round(max(latencies), 2) if latencies else None,
        },
    }


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def to_markdown(m: dict, rows: list[dict], split: str, prompt: str) -> str:
    sev, det = m["severity"], m["report_detection"]
    lines = [
        f"# Eval results: {split} split",
        "",
        f"Model `{m['model']}`, prompt/schema {prompt}, {m['items']} items, {m['parse_failures']} parse failures. "
        f"Generated by `python -m evals.run --split {split}`; do not edit by hand.",
        "",
        "## Report vs noise detection",
        "",
        "| class | precision | recall | support |",
        "|---|---|---|---|",
        *[
            f"| {c} | {pct(det[c]['precision'])} | {pct(det[c]['recall'])} | {det[c]['support']} |"
            for c in ["report", "noise"]
        ],
        "",
        f"## Severity ({sev['n']} NVD items)",
        "",
        f"A severity is published unless the guardrails withhold the vector. "
        f"Published for {pct(sev['coverage'])} of items; accuracy when published: "
        f"{pct(sev['accuracy_when_published'])}; correct over all NVD items (withheld counts as a miss): "
        f"{pct(sev['accuracy_all'])}. "
        f"Accuracy of the model's raw vector with no guardrails: {pct(sev['raw_accuracy'])} "
        f"({sev['raw_over_scored']} over-scored, {sev['raw_under_scored']} under-scored); "
        f"on the withheld items alone: {pct(sev['raw_accuracy_when_withheld'])}. "
        f"Raw base score minus NVD base score: mean {sev['raw_score_bias']:+}, "
        f"mean absolute {sev['raw_score_mae']}.",
        "",
        "| severity | precision | recall | support | predicted |",
        "|---|---|---|---|---|",
        *[
            f"| {s} | {pct(v['precision'])} | {pct(v['recall'])} | {v['support']} | {v['predicted']} |"
            for s, v in sev["per_class"].items()
        ],
        "",
        "Confusion matrix (rows = NVD label, columns = published prediction):",
        "",
        "| NVD \\ predicted | " + " | ".join(PRED_SEVERITIES) + " |",
        "|---|" + "---|" * len(PRED_SEVERITIES),
        *[
            f"| {g} | " + " | ".join(str(sev["confusion"].get(g, {}).get(p, 0)) for p in PRED_SEVERITIES) + " |"
            for g in SEVERITIES
        ],
        "",
        "Severity accuracy by the pipeline's own confidence:",
        "",
        "| confidence | n | accuracy |",
        "|---|---|---|",
        *[f"| {c} | {v['n']} | {pct(v['accuracy'])} |" for c, v in m["severity_accuracy_by_confidence"].items()],
        "",
        "## CWE",
        "",
        f"- Exact match with NVD primary CWE: {pct(m['cwe']['exact'])}",
        f"- Matches any CWE NVD lists for the CVE: {pct(m['cwe']['in_any_nvd_cwe'])}",
        f"- Exact, or a direct parent/child of the NVD primary CWE in MITRE's Research view (CWE-1000; "
        f"lenient): {pct(m['cwe']['parent_or_child'])}",
        f"- Answered `unknown`: {pct(m['cwe']['unknown'])}",
        "",
        "## CVSS v3.1 vector",
        "",
        f"- Exact match, published vector (withheld counts as a miss): {pct(m['cvss_vector']['exact_published'])}",
        f"- Exact match, model's raw vector: {pct(m['cvss_vector']['exact_raw'])}",
        "",
        "| metric | " + " | ".join(m["cvss_vector"]["per_metric_raw"]) + " |",
        "|---|" + "---|" * 8,
        "| agreement | " + " | ".join(pct(v) for v in m["cvss_vector"]["per_metric_raw"].values()) + " |",
        "",
        "## Thin and vague reports",
        "",
        f"{m['thin_and_vague']['n']} items: {m['thin_and_vague']['detected_as_report']} detected as reports, "
        f"{m['thin_and_vague']['low_confidence']} low confidence, "
        f"{m['thin_and_vague']['vector_withheld']} with the CVSS vector withheld.",
        "",
        "## Cost and latency (recorded when the responses were generated)",
        "",
        f"{m['cost']['input_tokens']:,} input + {m['cost']['output_tokens']:,} output tokens, "
        f"about ${m['cost']['usd']:.4f}. "
        + (
            f"Latency per call: mean {m['cost']['latency_s_mean']} s, median {m['cost']['latency_s_p50']} s, "
            f"max {m['cost']['latency_s_max']} s."
            if m["cost"]["latency_s_mean"] is not None
            else "Run through the Batch API (half price, no per-call latency)."
        ),
        "",
        "## Per item",
        "",
        "| id | kind | NVD severity | predicted | raw | NVD CWE | predicted CWE | confidence | flags |",
        "|---|---|---|---|---|---|---|---|---|",
        *[
            f"| {r['id']} | {r['kind']} | {r['severity'] or '-'} | {r.get('pred_severity', 'FAIL')} | "
            f"{r.get('raw_severity', '-')} | {r['cwe'] or '-'} | {r.get('pred_cwe', '-')} | "
            f"{r.get('confidence', '-')} | {', '.join(r.get('flags', [])) or '-'} |"
            for r in rows
        ],
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--split", choices=RESULTS, default="dev")
    parser.add_argument("--offline", action="store_true", help="Never call the API; fail on unrecorded items.")
    parser.add_argument("--check", action="store_true", help="Fail if metrics differ from the committed results.")
    parser.add_argument("--model", default=MODEL, help="Ignored with --check, which uses the committed results' model.")
    parser.add_argument("--prompt", choices=PROMPTS, default=PROMPT_VERSION, help="Ignored with --check.")
    parser.add_argument("--rpm", type=float, default=10, help="Max live API calls per minute (default 10).")
    args = parser.parse_args()

    results_json, results_md = HERE / f"{RESULTS[args.split]}.json", HERE / f"{RESULTS[args.split]}.md"
    committed_file = json.loads(results_json.read_text()) if args.check else None
    committed = committed_file["metrics"] if committed_file else None
    model = committed["model"] if committed else args.model
    prompt = PROMPTS[committed_file["prompt"]] if committed_file else PROMPTS[args.prompt]

    items = [json.loads(line) for line in (HERE / f"{args.split}.jsonl").read_text().splitlines() if line]
    rows, live = [], 0
    for item in items:
        row, was_live = run_item(item, model, args.offline, prompt)
        rows.append(row)
        if was_live:
            live += 1
            time.sleep(60 / args.rpm)  # stay under the account's requests-per-minute limit
    metrics = compute(rows, model)
    print(f"{args.split}: {len(rows)} items on {model}, prompt {prompt.version}, {live} live calls", file=sys.stderr)

    if committed:
        if committed != json.loads(json.dumps(metrics)):
            print(f"metrics differ from {results_json}", file=sys.stderr)
            return 1
        print(f"metrics match {results_json}", file=sys.stderr)
        return 0

    results_json.write_text(json.dumps({"prompt": prompt.version, "metrics": metrics, "rows": rows}, indent=2) + "\n")
    results_md.write_text(to_markdown(metrics, rows, args.split, prompt.version))
    print(f"wrote {results_md} and {results_json.name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
