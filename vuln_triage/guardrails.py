"""Turn the model's proposal into a TriageResult, trusting nothing we can check in code."""

import re

from cvss import CVSS3

from vuln_triage.schema import Confidence, ModelTriage, TriageResult

THIN_REPORT_CHARS = 120  # 200 flagged a quarter of real NVD descriptions as thin in the first eval
METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
MAX_GUESSED_METRICS = 4  # more guesses than this and we withhold the vector entirely


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def quote_in_report(quote: str, report: str) -> bool:
    """A quote counts only if it appears in the report (ignoring case and whitespace)."""
    q = _normalize(quote)
    return bool(q) and q in _normalize(report)


def score_vector(vector: str) -> tuple[float, str]:
    """Base score and severity from a CVSS v3.1 vector, computed by the cvss library."""
    c = CVSS3(vector)
    return float(c.scores()[0]), c.severities()[0]


def proposed_vector(proposal: ModelTriage) -> str:
    """The model's full CVSS v3.1 vector, before any evidence check."""
    return "CVSS:3.1/" + "/".join(f"{name}:{getattr(proposal.cvss, name).value}" for name in METRIC_ORDER)


def _cap(conf: Confidence, cap: Confidence) -> Confidence:
    order: list[Confidence] = ["low", "medium", "high"]
    return order[min(order.index(conf), order.index(cap))]


def finalize(proposal: ModelTriage, report: str) -> TriageResult:
    if not proposal.is_vulnerability_report:
        return TriageResult(
            is_vulnerability_report=False,
            summary=proposal.summary,
            affected_product="unknown",
            cwe="unknown",
            cvss_v31_vector="unknown",
            cvss_score=None,
            severity="unknown",
            recommended_next_step="Not a vulnerability report. Route back to sender; do not triage.",
            confidence="low",
            evidence_quotes=[],
            guessed_metrics=[],
            flags=["not_a_vulnerability_report"],
        )

    flags: list[str] = []
    confidence = proposal.confidence

    thin = len(report.strip()) < THIN_REPORT_CHARS
    if thin:
        flags.append("thin_report")
        confidence = "low"

    verified = [q for q in proposal.evidence_quotes if quote_in_report(q.quote, report)]
    if dropped := len(proposal.evidence_quotes) - len(verified):
        flags.append(f"dropped_{dropped}_unverified_quotes")
        confidence = _cap(confidence, "medium")
    if not verified:
        flags.append("no_verified_evidence")
        confidence = "low"

    cwe = proposal.cwe if re.fullmatch(r"CWE-\d+", proposal.cwe) else "unknown"
    if cwe != proposal.cwe and proposal.cwe != "unknown":
        flags.append("invalid_cwe_format")

    guessed = [n for n in METRIC_ORDER if not quote_in_report(getattr(proposal.cvss, n).quote, report)]
    vector = proposed_vector(proposal)
    if len(guessed) > MAX_GUESSED_METRICS:
        flags.append("cvss_mostly_guessed")
        confidence = "low"
        vector = "unknown"
    elif thin:  # a two-line report cannot support eight metrics, whatever the quotes say
        vector = "unknown"
    elif guessed:
        confidence = _cap(confidence, "medium")

    score, severity = score_vector(vector) if vector != "unknown" else (None, "unknown")

    return TriageResult(
        is_vulnerability_report=True,
        summary=proposal.summary,
        affected_product=proposal.affected_product,
        cwe=cwe,
        cvss_v31_vector=vector,
        cvss_score=score,
        severity=severity,
        recommended_next_step=proposal.recommended_next_step,
        confidence=confidence,
        evidence_quotes=verified,
        guessed_metrics=guessed,
        flags=flags,
    )
