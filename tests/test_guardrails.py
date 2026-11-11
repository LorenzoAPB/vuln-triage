from conftest import NETWORK, REPORT, guess_all, proposal

from vuln_triage.guardrails import finalize, quote_in_report, score_vector


def test_score_comes_from_the_cvss_library():
    assert score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == (9.8, "Critical")
    assert score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N") == (6.5, "Medium")
    assert score_vector("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N") == (3.1, "Low")


def test_quote_matching_ignores_case_and_whitespace_only():
    assert quote_in_report("a REMOTE   unauthenticated\nattacker", REPORT)
    assert not quote_in_report("a remote attacker without credentials", REPORT)  # paraphrase
    assert not quote_in_report("", REPORT)
    assert not quote_in_report("   ", REPORT)


def test_well_evidenced_report_publishes_a_computed_score():
    result = finalize(proposal(), REPORT)
    assert result.cvss_v31_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
    assert (result.cvss_score, result.severity) == (6.5, "Medium")
    assert result.guessed_metrics == ["S"]
    assert result.confidence == "medium"  # one guessed metric caps confidence
    assert result.flags == []


def test_invented_quotes_are_dropped_and_flagged():
    fake = {"claim": "exploited in the wild", "quote": "actively exploited in the wild"}
    p = proposal(evidence_quotes=[*proposal().evidence_quotes, fake])
    result = finalize(p, REPORT)
    assert [q.quote for q in result.evidence_quotes] == ["ExampleCMS 4.2.0 through 4.2.3"]
    assert "dropped_1_unverified_quotes" in result.flags
    assert result.confidence == "medium"


def test_no_verified_evidence_means_low_confidence():
    result = finalize(proposal(evidence_quotes=[{"claim": "x", "quote": "not in the report"}]), REPORT)
    assert result.evidence_quotes == []
    assert "no_verified_evidence" in result.flags
    assert result.confidence == "low"


def test_mostly_guessed_vector_is_withheld():
    result = finalize(guess_all(proposal(), keep={"AV", "C", "I"}), REPORT)
    assert result.guessed_metrics == ["AC", "PR", "UI", "S", "A"]
    assert (result.cvss_v31_vector, result.cvss_score, result.severity) == ("unknown", None, "unknown")
    assert "cvss_mostly_guessed" in result.flags
    assert result.confidence == "low"


def test_half_guessed_vector_is_still_published():
    result = finalize(guess_all(proposal(), keep={"AV", "PR", "UI", "C"}), REPORT)
    assert len(result.guessed_metrics) == 4
    assert result.cvss_score == 6.5


def test_thin_report_withholds_the_vector_even_with_quotes():
    thin = "XSS in ExampleCMS search. A remote unauthenticated attacker can send a victim a crafted link."
    p = proposal(evidence_quotes=[{"claim": "xss", "quote": "XSS in ExampleCMS search."}])
    result = finalize(p, thin)
    assert "thin_report" in result.flags
    assert result.cvss_v31_vector == "unknown"
    assert result.confidence == "low"


def test_malformed_cwe_becomes_unknown():
    result = finalize(proposal(cwe="CWE79 (XSS)"), REPORT)
    assert result.cwe == "unknown"
    assert "invalid_cwe_format" in result.flags
    assert finalize(proposal(cwe="unknown"), REPORT).flags == []


def test_non_report_is_refused_with_nothing_filled_in():
    result = finalize(proposal(is_vulnerability_report=False, confidence="high"), REPORT)
    assert result.is_vulnerability_report is False
    assert result.flags == ["not_a_vulnerability_report"]
    assert (result.cwe, result.cvss_v31_vector, result.cvss_score) == ("unknown", "unknown", None)
    assert result.evidence_quotes == []
    assert result.confidence == "low"


def test_one_quote_cannot_justify_more_than_three_metrics():
    p = proposal()
    cvss = p.cvss.model_dump()
    for name in ["AV", "AC", "PR", "UI"]:
        cvss[name]["quote"] = NETWORK  # four metrics, one sentence
    result = finalize(p.model_copy(update={"cvss": type(p.cvss).model_validate(cvss)}), REPORT)
    assert "cvss_quote_overused" in result.flags
    assert result.guessed_metrics == ["AV", "AC", "PR", "UI", "S"]
    assert result.cvss_v31_vector == "unknown"


def test_cwe_needs_a_quote_describing_the_weakness():
    result = finalize(proposal(cwe_quote="stored XSS in the comments field"), REPORT)
    assert result.cwe == "unknown"
    assert "cwe_without_evidence" in result.flags
