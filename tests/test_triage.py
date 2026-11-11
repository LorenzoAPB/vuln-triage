import pytest
from conftest import REPORT, FakeOpenAI

from vuln_triage.triage import CacheMiss, TriageError, Usage, call_model


def test_call_is_cached_on_disk(tmp_path, fake_openai):
    first, usage1 = call_model(REPORT, "gpt-5-mini", tmp_path)
    second, usage2 = call_model(REPORT, "gpt-5-mini", tmp_path)
    assert fake_openai.calls == 1
    assert first == second
    assert (usage1.cached, usage2.cached) == (False, True)
    assert usage2.input_tokens == 1000  # recorded usage survives the cache


def test_cache_key_depends_on_the_model(tmp_path, fake_openai):
    call_model(REPORT, "gpt-5-mini", tmp_path)
    call_model(REPORT, "gpt-5.4-nano", tmp_path)
    assert fake_openai.calls == 2


def test_offline_mode_never_calls_the_api(tmp_path, fake_openai):
    with pytest.raises(CacheMiss):
        call_model(REPORT, "gpt-5-mini", tmp_path, offline=True)
    assert fake_openai.calls == 0


def test_missing_parsed_output_is_a_triage_error(tmp_path, monkeypatch):
    monkeypatch.setattr("vuln_triage.triage.OpenAI", FakeOpenAI(None))
    with pytest.raises(TriageError):
        call_model(REPORT, "gpt-5-mini", tmp_path)
    assert list(tmp_path.iterdir()) == []  # failures are not cached


def test_cost_uses_per_model_prices():
    usage = Usage(model="gpt-5-mini", input_tokens=1_000_000, output_tokens=1_000_000, latency_s=1.0, cached=False)
    assert usage.cost_usd == pytest.approx(0.25 + 2.00)
