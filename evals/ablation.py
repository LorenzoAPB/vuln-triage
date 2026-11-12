"""Dev-split ablations: which change moved which metric. Replays recordings only (no API calls).

Each row is one configuration, scored on the NVD-labeled items of a dev split: the 36 NVD
descriptions of `dev` (evals/ablation.md) or the 30 Exploit-DB write-ups of `writeups-dev`
(evals/writeups_ablation.md). Record missing responses first with evals.batch.

  python -m evals.ablation [--split writeups-dev]           # regenerate
  python -m evals.ablation [--split writeups-dev] --check   # CI: fail if the numbers changed
"""

import json
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

from evals.run import compute, load_split, pct, run_item
from vuln_triage.guardrails import METRIC_ORDER, score_vector
from vuln_triage.retrieval import pool_index
from vuln_triage.triage import PROMPTS

HERE = Path(__file__).parent
K = 5  # neighbours, as in prompt v4

# (label, model, prompt version, override of the guardrail rule or None, post-processing)
CONFIGS = [
    ("Nearest-neighbour vote (k=5), no LLM", None, None, None, "knn_vote"),
    ("v3: withhold mostly-inferred vectors", "gpt-4o-mini", "v3", None, None),
    ("v4: v3 prompt, publish as provisional", "gpt-4o-mini", "v4", None, None),
    ("exp-knn: + 5 similar NVD CVEs in the prompt, withhold rule", "gpt-4o-mini", "exp-knn", False, None),
    ("exp-knn: + 5 similar NVD CVEs in the prompt", "gpt-4o-mini", "exp-knn", None, None),
    ("exp-knn, inferred metrics taken from the neighbour vote", "gpt-4o-mini", "exp-knn", None, "knn_fill"),
    ("v3: withhold mostly-inferred vectors", "gpt-5-mini", "v3", None, None),
    ("v4: v3 prompt, publish as provisional", "gpt-5-mini", "v4", None, None),
    ("exp-knn: + 5 similar NVD CVEs in the prompt, withhold rule", "gpt-5-mini", "exp-knn", False, None),
    ("exp-knn: + 5 similar NVD CVEs in the prompt", "gpt-5-mini", "exp-knn", None, None),
    ("exp-low: v4 at low reasoning effort", "gpt-5-mini", "exp-low", None, None),
    ("exp-knn-low: exp-knn at low reasoning effort", "gpt-5-mini", "exp-knn-low", None, None),
]
WRITEUP_CONFIGS = [
    ("Nearest-neighbour vote (k=5), no LLM", None, None, None, "knn_vote"),
    ("v4: the NVD-tuned prompt", "gpt-5-mini", "v4", None, None),
    ("v5: v4 + rules for reading exploit code and requests", "gpt-5-mini", "v5", None, None),
]
ABLATIONS = {  # split: (configurations, output file stem, description of the items)
    "dev": (CONFIGS, "ablation", "36 NVD items of the dev split (June-July and September-October 2023)"),
    "writeups-dev": (
        WRITEUP_CONFIGS,
        "writeups_ablation",
        "30 Exploit-DB write-ups of the writeups-dev split (CVE-2020/2021, NVD v3.1 labels)",
    ),
}


def vote(text: str) -> tuple[dict[str, str], str]:
    """Most common value per CVSS metric, and most common CWE, among the K nearest pool CVEs."""
    neighbours = pool_index().nearest(text, K)
    metrics = [dict(p.split(":") for p in d["vector"].split("/")[1:]) for d in neighbours]
    return (
        {m: Counter(x[m] for x in metrics).most_common(1)[0][0] for m in METRIC_ORDER},
        Counter(d["cwe"] for d in neighbours).most_common(1)[0][0],
    )


def as_vector(metrics: dict[str, str]) -> str:
    return "CVSS:3.1/" + "/".join(f"{m}:{metrics[m]}" for m in METRIC_ORDER)


def knn_row(item: dict) -> dict:
    metrics, cwe = vote(item["text"])
    vector = as_vector(metrics)
    severity = score_vector(vector)[1]
    zero = {"input_tokens": 0, "output_tokens": 0, "latency_s": None, "cost_usd": 0.0}
    return {k: item.get(k) for k in ["id", "kind", "is_report", "severity", "cwe", "cwe_all", "vector"]} | {
        "parse_failure": None,
        "pred_is_report": True,
        "pred_severity": severity,
        "pred_cwe": cwe,
        "pred_vector": vector,
        "raw_vector": vector,
        "raw_severity": severity,
        "raw_metrics": metrics,
        "confidence": "low",
        "flags": [],
        "guessed_metrics": [],
        "usage": zero,
    }


def knn_fill(row: dict, item: dict) -> dict:
    """Keep the model's metrics that have verified quotes; take the rest from the neighbour vote."""
    if row["pred_vector"] == "unknown":  # thin reports stay withheld
        return row
    voted, _ = vote(item["text"])
    metrics = {m: voted[m] if m in row["guessed_metrics"] else v for m, v in row["raw_metrics"].items()}
    vector = as_vector(metrics)
    severity = score_vector(vector)[1]
    return row | {
        "pred_vector": vector,
        "pred_severity": severity,
        "raw_vector": vector,
        "raw_severity": severity,
        "raw_metrics": metrics,
    }


def evaluate(split: str, model: str | None, prompt: str | None, publish: bool | None, post: str | None) -> dict:
    items = [i for i in load_split(split) if i.get("vector")]
    rows = []
    for item in items:
        if post == "knn_vote":
            rows.append(knn_row(item))
            continue
        config = PROMPTS[prompt] if publish is None else replace(PROMPTS[prompt], publish_inferred=publish)
        row, _ = run_item(item, model, True, config)
        rows.append(knn_fill(row, item) if post == "knn_fill" else row)
    m = compute(rows, model or "none")
    sev, cwe, vec = m["severity"], m["cwe"], m["cvss_vector"]
    return {
        "coverage": sev["coverage"],
        "accuracy_when_published": sev["accuracy_when_published"],
        "accuracy_all": sev["accuracy_all"],
        "over_under": [sev["raw_over_scored"], sev["raw_under_scored"]],
        "bias": sev["raw_score_bias"],
        "mae": sev["raw_score_mae"],
        "within_one_band": sev["raw_within_one_band"],
        "within_1_point": sev["raw_score_within_1"],
        "vector_exact": vec["exact_raw"],
        "per_metric": vec["per_metric_raw"],
        "cwe_exact": cwe["exact"],
        "cwe_lenient": cwe["parent_or_child"],
        "cwe_unknown": cwe["unknown"],
        "usd": m["cost"]["usd"],
    }


def main() -> int:
    split = sys.argv[sys.argv.index("--split") + 1] if "--split" in sys.argv else "dev"
    configs, stem, described = ABLATIONS[split]
    results = [
        {"label": label, "model": model or "-", "prompt": prompt or "-", **evaluate(split, model, prompt, *rest)}
        for label, model, prompt, *rest in configs
    ]
    path = HERE / f"{stem}.json"
    if "--check" in sys.argv:
        same = json.loads(path.read_text()) == json.loads(json.dumps(results))
        print("ablation matches" if same else "ablation differs from ablation.json", file=sys.stderr)
        return 0 if same else 1
    path.write_text(json.dumps(results, indent=2) + "\n")
    lines = [
        f"# Dev-split ablation: {split}",
        "",
        f"{described}. Generated by `python -m evals.ablation --split {split}` from recorded responses; "
        "do not edit by hand. Severity accuracy (all) counts a withheld vector as a miss. Over/under, bias, "
        "MAE, within one band or 1.0 point, vector exact, per-metric, and CWE use the "
        "vector the configuration proposes (the model's raw vector, or the filled/voted one).",
        "",
        "| Configuration | Model | Prompt | Published | Sev. acc. when published | Sev. acc. (all) "
        "| Over / under | Score bias | MAE | Within one band | Within 1.0 point | Vector exact "
        "| AV / AC / PR / UI / S / C / I / A | CWE exact | CWE lenient | CWE unknown | Cost |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r['label']} | {r['model']} | {r['prompt']} | {pct(r['coverage'])} | "
            f"{pct(r['accuracy_when_published'])} | {pct(r['accuracy_all'])} | {r['over_under'][0]} / "
            f"{r['over_under'][1]} | {r['bias']:+} | {r['mae']} | {pct(r['within_one_band'])} | "
            f"{pct(r['within_1_point'])} | {pct(r['vector_exact'])} | "
            + " / ".join(pct(v) for v in r["per_metric"].values())
            + f" | {pct(r['cwe_exact'])} | {pct(r['cwe_lenient'])} | {pct(r['cwe_unknown'])} | ${r['usd']:.4f} |"
        )
    (HERE / f"{stem}.md").write_text("\n".join(lines) + "\n")
    print(f"wrote {HERE / stem}.md", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
