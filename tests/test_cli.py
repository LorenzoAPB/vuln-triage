import json
from pathlib import Path

import pytest
from conftest import REPORT, proposal

from vuln_triage import cli
from vuln_triage.triage import TriageError, Usage


def run(monkeypatch, tmp_path: Path, answers: list[str], extra_args: list[str] = ()) -> dict:
    """Run `vuln-triage triage` with scripted keyboard answers; return the logged record."""
    report = tmp_path / "report.txt"
    report.write_text(REPORT)
    monkeypatch.setattr(cli, "LOG_PATH", tmp_path / "triage.jsonl")
    answers_iter = iter(answers)

    def fake_input(prompt: str) -> str:
        try:
            return next(answers_iter)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr("builtins.input", fake_input)
    assert cli.main(["triage", str(report), *extra_args]) == 0
    return json.loads((tmp_path / "triage.jsonl").read_text().splitlines()[-1])


@pytest.fixture
def stub_model(monkeypatch):
    usage = Usage(model="gpt-5-mini", input_tokens=1200, output_tokens=800, latency_s=2.5, cached=False)
    monkeypatch.setattr(cli, "call_model", lambda report, model: (proposal(), usage))


def test_approve_unchanged(monkeypatch, tmp_path, stub_model):
    record = run(monkeypatch, tmp_path, ["a"])
    assert record["decision"] == "approved"
    assert record["overrides"] == {}
    assert record["final"]["severity"] == "Medium"
    assert record["input_tokens"] == 1200
    assert record["cost_usd"] == pytest.approx((1200 * 0.25 + 800 * 2.00) / 1e6)


def test_edited_vector_recomputes_score_and_logs_overrides(monkeypatch, tmp_path, stub_model):
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    out = tmp_path / "final.json"
    record = run(monkeypatch, tmp_path, ["e", "vector", vector, "e", "cwe", "CWE-80", "a"], ["--out", str(out)])
    assert record["overrides"]["cvss_v31_vector"]["human"] == vector
    assert record["overrides"]["cvss_score"] == {"model": 6.5, "human": 6.1}
    assert "severity" not in record["overrides"]  # 6.1 is still Medium
    assert record["overrides"]["guessed_metrics"] == {"model": ["S"], "human": []}
    assert record["overrides"]["cwe"] == {"model": "CWE-79", "human": "CWE-80"}
    assert json.loads(out.read_text())["cvss_score"] == 6.1


def test_invalid_edits_are_refused(monkeypatch, tmp_path, stub_model):
    record = run(monkeypatch, tmp_path, ["e", "vector", "CVSS:3.1/AV:X", "e", "severity", "Severe", "a"])
    assert record["overrides"] == {}


def test_severity_override_is_logged(monkeypatch, tmp_path, stub_model):
    record = run(monkeypatch, tmp_path, ["e", "severity", "High", "a"])
    assert record["overrides"] == {"severity": {"model": "Medium", "human": "High"}}


def test_reject_logs_reason_and_no_final_result(monkeypatch, tmp_path, stub_model):
    record = run(monkeypatch, tmp_path, ["r", "duplicate of PSIRT-123"])
    assert record["decision"] == "rejected"
    assert record["reject_reason"] == "duplicate of PSIRT-123"
    assert record["final"] is None


def test_no_decision_is_logged_as_abandoned(monkeypatch, tmp_path, stub_model):
    record = run(monkeypatch, tmp_path, [])
    assert record["decision"] == "abandoned"
    assert record["final"] is None


def test_parse_failure_is_logged(monkeypatch, tmp_path):
    def failing(report, model):
        raise TriageError("no parsed output (status=incomplete)")

    monkeypatch.setattr(cli, "call_model", failing)
    monkeypatch.setattr(cli, "LOG_PATH", tmp_path / "triage.jsonl")
    report = tmp_path / "r.txt"
    report.write_text(REPORT)
    assert cli.main(["triage", str(report)]) == 2
    record = json.loads((tmp_path / "triage.jsonl").read_text())
    assert record["event"] == "parse_failure"


def test_end_to_end_with_mocked_api(monkeypatch, tmp_path, fake_openai):
    """Real call_model, guardrails, and CLI; only the OpenAI client is fake."""
    monkeypatch.chdir(tmp_path)
    first = run(monkeypatch, tmp_path, ["a"])
    second = run(monkeypatch, tmp_path, ["a"])
    assert fake_openai.calls == 1
    assert (first["cached"], second["cached"]) == (False, True)
    assert first["final"]["cvss_v31_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
    assert first["flags"] == []
