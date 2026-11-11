"""What the model is allowed to return, and what we add in code."""

from typing import Literal

from pydantic import BaseModel, Field


class EvidenceQuote(BaseModel):
    claim: str = Field(description="The specific claim this quote supports, e.g. 'attack vector is network'.")
    quote: str = Field(description="Exact text copied from the report. Never paraphrase.")


class ModelTriage(BaseModel):
    """Fields the model fills in. Everything else is computed in code."""

    is_vulnerability_report: bool = Field(description="False if the text is not a security vulnerability report.")
    summary: str = Field(description="One or two sentences, only facts stated in the report.")
    affected_product: str = Field(description="Product and version range, or 'unknown'.")
    cwe: str = Field(description="Best-fit CWE id like 'CWE-79', or 'unknown'.")
    cvss_v31_vector: str = Field(description="Full CVSS:3.1 base vector, or 'unknown' if the report lacks enough detail.")
    recommended_next_step: str = Field(description="One concrete next action for a PSIRT analyst.")
    confidence: Literal["low", "medium", "high"] = Field(description="Low when the report is thin or vague.")
    evidence_quotes: list[EvidenceQuote]
