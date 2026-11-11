"""Pure metric functions, kept separate from the runner so they can be unit tested."""

from collections import Counter

SEVERITIES = ["Critical", "High", "Medium", "Low"]
METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def confusion(gold: list[str], pred: list[str]) -> dict[str, dict[str, int]]:
    """counts[gold_label][predicted_label]."""
    counts: dict[str, dict[str, int]] = {}
    for g, p in zip(gold, pred, strict=True):
        counts.setdefault(g, Counter())[p] += 1
    return {g: dict(c) for g, c in counts.items()}


def precision_recall(gold: list[str], pred: list[str], label: str) -> dict[str, float | int | None]:
    """Precision is None when the label was never predicted (undefined, not zero)."""
    tp = sum(g == label and p == label for g, p in zip(gold, pred, strict=True))
    predicted = sum(p == label for p in pred)
    support = sum(g == label for g in gold)
    return {
        "precision": tp / predicted if predicted else None,
        "recall": tp / support if support else None,
        "support": support,
        "predicted": predicted,
    }


def parse_vector(vector: str) -> dict[str, str]:
    """'CVSS:3.1/AV:N/AC:L/...' -> {'AV': 'N', 'AC': 'L', ...}; '' or 'unknown' -> {}."""
    if not vector.startswith("CVSS:3.1/"):
        return {}
    return dict(part.split(":") for part in vector.removeprefix("CVSS:3.1/").split("/"))


def metric_agreement(gold_vectors: list[str], pred_metrics: list[dict[str, str]]) -> dict[str, float]:
    """Share of items where each predicted base metric equals the gold one ('unknown' counts as wrong)."""
    gold = [parse_vector(v) for v in gold_vectors]
    return {m: sum(g[m] == p.get(m) for g, p in zip(gold, pred_metrics, strict=True)) / len(gold) for m in METRICS}


def cwe_related(pred: str, gold: str, parents: dict[str, list[str]]) -> bool:
    """Exact match, or one is a direct parent (ChildOf) of the other in MITRE's Research view."""
    return pred == gold or gold in parents.get(pred, []) or pred in parents.get(gold, [])
