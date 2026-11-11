import pytest

from evals.metrics import confusion, metric_agreement, parse_vector, precision_recall

GOLD = ["High", "High", "Low", "Medium"]
PRED = ["High", "unknown", "High", "Medium"]


def test_confusion_counts_gold_rows_by_predicted_column():
    assert confusion(GOLD, PRED) == {"High": {"High": 1, "unknown": 1}, "Low": {"High": 1}, "Medium": {"Medium": 1}}


def test_precision_and_recall():
    assert precision_recall(GOLD, PRED, "High") == {"precision": 0.5, "recall": 0.5, "support": 2, "predicted": 2}
    assert precision_recall(GOLD, PRED, "Medium")["precision"] == 1.0


def test_precision_is_undefined_when_never_predicted():
    result = precision_recall(GOLD, PRED, "Low")
    assert result["precision"] is None
    assert result["recall"] == 0.0


def test_parse_vector():
    assert parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["AV"] == "N"
    assert parse_vector("unknown") == {}


def test_metric_agreement():
    gold = ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"]
    pred = [parse_vector(gold[0]), {**parse_vector(gold[1]), "AV": "N", "C": "H"}]
    agreement = metric_agreement(gold, pred)
    assert agreement["AV"] == pytest.approx(0.5)
    assert agreement["C"] == pytest.approx(0.5)
    assert agreement["PR"] == 1.0
