"""Run the eval set through the real pipeline and write evals/results.{json,md}.

python -m evals.run             # call the API only for items not yet recorded
python -m evals.run --offline   # replay recorded responses only (what CI runs)
python -m evals.run --offline --check   # also fail if metrics differ from results.json
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from evals.metrics import SEVERITIES, confusion, metric_agreement, precision_recall
from vuln_triage.guardrails import METRIC_ORDER, finalize, proposed_vector, score_vector
from vuln_triage.triage import MODEL, TriageError, call_model

HERE = Path(__file__).parent
RECORDINGS = HERE / "recordings"
PRED_SEVERITIES = [*SEVERITIES, "None", "unknown"]


def run_item(item: dict, model: str, offline: bool) -> dict:
    row = {k: item.get(k) for k in ["id", "kind", "is_report", "severity", "cwe", "cwe_all", "vector"]}
    try:
        proposal, usage = call_model(item["text"], model, RECORDINGS, offline)
    except TriageError as e:
        return {**row, "parse_failure": str(e)}
    result = finalize(proposal, item["text"])
    raw_vector = proposed_vector(proposal) if result.is_vulnerability_report else "unknown"
    return {
        **row,
        "parse_failure": None,
        "pred_is_report": result.is_vulnerability_report,
        "pred_severity": result.severity,
        "pred_cwe": result.cwe,
        "pred_vector": result.cvss_v31_vector,
        "raw_vector": raw_vector,
        "raw_severity": score_vector(raw_vector)[1] if raw_vector != "unknown" else "unknown",
        "raw_metrics": {m: getattr(proposal.cvss, m).value for m in METRIC_ORDER},
        "confidence": result.confidence,
        "flags": result.flags,
        "guessed_metrics": result.guessed_metrics,
        "usage": {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "latency_s": usage.latency_s,
            "cost_usd": usage.cost_usd,
            "cached": usage.cached,
        },
    }


def compute(rows: list[dict], model: str) -> dict:
    ok = [r for r in rows if not r["parse_failure"]]
    nvd = [r for r in ok if r["kind"] == "nvd"]
    unclear = [r for r in ok if r["kind"] in ("thin", "vague")]

    gold_report = ["report" if r["is_report"] else "noise" for r in ok]
    pred_report = ["report" if r["pred_is_report"] else "noise" for r in ok]

    gold_sev = [r["severity"] for r in nvd]
    published = [r for r in nvd if r["pred_vector"] != "unknown"]
    usages = [r["usage"] for r in ok]
    latencies = [u["latency_s"] for u in usages]

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
            "raw_accuracy": sum(r["raw_severity"] == r["severity"] for r in nvd) / len(nvd),
            "raw_confusion": confusion(gold_sev, [r["raw_severity"] for r in nvd]),
        },
        "severity_accuracy_by_confidence": {
            c: {"n": len(group), "accuracy": sum(r["pred_severity"] == r["severity"] for r in group) / len(group)}
            for c in ["low", "medium", "high"]
            if (group := [r for r in nvd if r["confidence"] == c])
        },
        "cwe": {
            "exact": sum(r["pred_cwe"] == r["cwe"] for r in nvd) / len(nvd),
            "in_any_nvd_cwe": sum(r["pred_cwe"] in r["cwe_all"] for r in nvd) / len(nvd),
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
            "latency_s_mean": round(statistics.mean(latencies), 2),
            "latency_s_p50": round(statistics.median(latencies), 2),
            "latency_s_max": round(max(latencies), 2),
        },
    }


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def to_markdown(m: dict, rows: list[dict]) -> str:
    sev, det = m["severity"], m["report_detection"]
    lines = [
        "# Eval results",
        "",
        f"Model `{m['model']}`, {m['items']} items, {m['parse_failures']} parse failures. "
        "Generated by `python -m evals.run`; do not edit by hand.",
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
        f"A severity is only published when the CVSS vector passes the guardrails. "
        f"Published for {pct(sev['coverage'])} of items; accuracy when published: "
        f"{pct(sev['accuracy_when_published'])}. "
        f"Accuracy of the model's raw vector with no guardrails: {pct(sev['raw_accuracy'])}.",
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
        "## Cost and latency (recorded from the live run)",
        "",
        f"{m['cost']['input_tokens']:,} input + {m['cost']['output_tokens']:,} output tokens, "
        f"about ${m['cost']['usd']:.4f}. Latency per call: mean {m['cost']['latency_s_mean']} s, "
        f"median {m['cost']['latency_s_p50']} s, max {m['cost']['latency_s_max']} s.",
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
    parser.add_argument("--offline", action="store_true", help="Never call the API; fail on unrecorded items.")
    parser.add_argument("--check", action="store_true", help="Fail if metrics differ from evals/results.json.")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--rpm", type=float, default=10, help="Max live API calls per minute (default 10).")
    args = parser.parse_args()

    items = [json.loads(line) for line in (HERE / "dataset.jsonl").read_text().splitlines() if line]
    rows = []
    for item in items:
        rows.append(run_item(item, args.model, args.offline))
        if (usage := rows[-1].get("usage")) and not usage["cached"]:
            time.sleep(60 / args.rpm)  # stay under the account's requests-per-minute limit
    metrics = compute(rows, args.model)

    live = sum(1 for r in rows if r.get("usage") and not r["usage"]["cached"])
    live_cost = sum(r["usage"]["cost_usd"] for r in rows if r.get("usage") and not r["usage"]["cached"])
    print(f"{len(rows)} items, {live} live API calls this run (${live_cost:.4f})", file=sys.stderr)

    if args.check:
        committed = json.loads((HERE / "results.json").read_text())["metrics"]
        if committed != json.loads(json.dumps(metrics)):
            print("metrics differ from evals/results.json", file=sys.stderr)
            return 1
        print("metrics match evals/results.json", file=sys.stderr)
        return 0

    (HERE / "results.json").write_text(json.dumps({"metrics": metrics, "rows": rows}, indent=2) + "\n")
    (HERE / "results.md").write_text(to_markdown(metrics, rows))
    print(json.dumps(metrics["severity"]["per_class"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
