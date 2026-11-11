"""What the model may return (ModelTriage), and the result we build from it in code (TriageResult)."""

from typing import Literal

from pydantic import BaseModel, Field

Confidence = Literal["low", "medium", "high"]


class EvidenceQuote(BaseModel):
    claim: str = Field(description="The specific claim this quote supports.")
    quote: str = Field(description="Exact text copied from the report. Never paraphrase.")


QUOTE = Field(description="Exact report text supporting this value, or '' if the value is inferred.")


class AttackVector(BaseModel):
    value: Literal["N", "A", "L", "P"]
    quote: str = QUOTE


class AttackComplexity(BaseModel):
    value: Literal["L", "H"]
    quote: str = QUOTE


class PrivilegesRequired(BaseModel):
    value: Literal["N", "L", "H"]
    quote: str = QUOTE


class UserInteraction(BaseModel):
    value: Literal["N", "R"]
    quote: str = QUOTE


class Scope(BaseModel):
    value: Literal["U", "C"]
    quote: str = QUOTE


class Impact(BaseModel):
    value: Literal["H", "L", "N"]
    quote: str = QUOTE


class CvssProposal(BaseModel):
    """One field per CVSS v3.1 base metric, so each value carries its own evidence.

    There is no 'unknown' value: the model always proposes, and code decides from the evidence
    whether the vector is published (see guardrails.finalize).
    """

    AV: AttackVector
    AC: AttackComplexity
    PR: PrivilegesRequired
    UI: UserInteraction
    S: Scope
    C: Impact
    I: Impact
    A: Impact


class ModelTriage(BaseModel):
    """Fields the model fills in. Score, severity and flags are computed in code."""

    is_vulnerability_report: bool = Field(description="False if the text is not a security vulnerability report.")
    summary: str = Field(description="One or two sentences, only facts stated in the report.")
    affected_product: str = Field(description="Product and version range, or 'unknown'.")
    cwe: str = Field(description="Most specific CWE id for the weakness described, like 'CWE-79', or 'unknown'.")
    cwe_quote: str = Field(description="Exact report text describing the weakness, or '' if cwe is 'unknown'.")
    cvss: CvssProposal
    recommended_next_step: str = Field(description="One concrete next action for a PSIRT analyst.")
    confidence: Confidence = Field(description="Low when the report is thin or vague.")
    evidence_quotes: list[EvidenceQuote]


class TriageResult(BaseModel):
    """The draft a human reviews. Nothing here is final until a human approves it."""

    is_vulnerability_report: bool
    summary: str
    affected_product: str
    cwe: str
    cvss_v31_vector: str
    cvss_score: float | None
    severity: str
    recommended_next_step: str
    confidence: Confidence
    evidence_quotes: list[EvidenceQuote]
    guessed_metrics: list[str]
    flags: list[str]
