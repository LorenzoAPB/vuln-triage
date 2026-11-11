"""Before/after table from two results files, recomputing both with the current metric code.

python -m evals.compare evals/history/dev-v2-gpt-5-nano.json evals/history/dev-v3b-gpt-5-nano.json

Columns are labeled with each file's model and prompt version. Only a same-model pair isolates the prompt change.
"""

import json
import sys
from pathlib import Path

from evals.run import compute, pct


def rows_of(path: str) -> tuple[str, list[dict], str]:
    data = json.loads(Path(path).read_text())
    return data["metrics"]["model"], data["rows"], data.get("prompt", "see file name")


def table(before_path: str, after_path: str) -> str:
    (model_a, rows_a, prompt_a), (model_b, rows_b, prompt_b) = rows_of(before_path), rows_of(after_path)
    a, b = compute(rows_a, model_a), compute(rows_b, model_b)
    lines = [
        f"| Metric | Before (`{before_path.split('/')[-1]}`) | After (`{after_path.split('/')[-1]}`) |",
        "|---|---|---|",
    ]

    def add(name: str, get, fmt=pct) -> None:
        lines.append(f"| {name} | {fmt(get(a))} | {fmt(get(b))} |")

    add("Model", lambda m: m["model"], str)
    lines.append(f"| Prompt/schema | {prompt_a} | {prompt_b} |")
    add("Items", lambda m: m["items"], str)
    add("Report recall", lambda m: m["report_detection"]["report"]["recall"])
    add("Noise recall", lambda m: m["report_detection"]["noise"]["recall"])
    add("Severity published (coverage)", lambda m: m["severity"]["coverage"])
    add("Severity accuracy when published", lambda m: m["severity"]["accuracy_when_published"])
    add("Severity correct, all NVD items (withheld = miss)", lambda m: m["severity"]["accuracy_all"])
    add("Severity accuracy, raw vector", lambda m: m["severity"]["raw_accuracy"])
    add(
        "Raw vectors over-scored / under-scored",
        lambda m: (m["severity"]["raw_over_scored"], m["severity"]["raw_under_scored"]),
        lambda t: f"{t[0]} / {t[1]}",
    )
    add("Raw minus NVD base score, mean", lambda m: m["severity"]["raw_score_bias"], lambda x: f"{x:+}")
    add("Raw minus NVD base score, mean absolute", lambda m: m["severity"]["raw_score_mae"], str)
    for s in ["Critical", "High", "Medium", "Low"]:
        add(f"{s} recall", lambda m, s=s: m["severity"]["per_class"][s]["recall"])
    add("CWE exact", lambda m: m["cwe"]["exact"])
    add("CWE parent/child (lenient)", lambda m: m["cwe"]["parent_or_child"])
    add("CWE unknown", lambda m: m["cwe"]["unknown"])
    add("Vector exact, raw", lambda m: m["cvss_vector"]["exact_raw"])
    for metric in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
        add(f"{metric} agreement", lambda m, k=metric: m["cvss_vector"]["per_metric_raw"][k])
    add("Cost (USD)", lambda m: m["cost"]["usd"], lambda x: f"${x:.4f}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(table(sys.argv[1], sys.argv[2]))
