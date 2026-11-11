import pytest
from conftest import REPORT, FakeOpenAI

from vuln_triage.retrieval import Index
from vuln_triage.triage import PROMPTS, CacheMiss, TriageError, Usage, call_model, user_message


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


def test_batch_calls_cost_half():
    usage = Usage(
        model="gpt-5-mini", input_tokens=1_000_000, output_tokens=1_000_000, latency_s=None, cached=False, batch=True
    )
    assert usage.cost_usd == pytest.approx((0.25 + 2.00) / 2)


def test_exp_knn_appends_the_nearest_nvd_example_and_v4_does_not():
    message = user_message(REPORT, PROMPTS["exp-knn"])
    assert message.startswith("REPORT:\n" + REPORT)
    assert "NVD: CWE-79, CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" in message
    assert "CWE-787" not in message  # shares no words with the report
    assert user_message(REPORT, PROMPTS["v4"]) == REPORT


def test_nearest_ranks_by_shared_rare_words():
    index = Index([{"text": "sql injection in login"}, {"text": "heap overflow in image decoder"}])
    assert index.nearest("image decoder overflow", k=1)[0]["text"] == "heap overflow in image decoder"
