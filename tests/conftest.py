from types import SimpleNamespace

import pytest

from vuln_triage.retrieval import Index
from vuln_triage.schema import ModelTriage

REPORT = (
    "ExampleCMS 4.2.0 through 4.2.3 does not neutralize the q parameter of /search. "
    "A remote unauthenticated attacker can send a victim a crafted link that runs script in the "
    "victim's browser and reads their session cookie."
)
NETWORK = "A remote unauthenticated attacker"
LINK = "send a victim a crafted link"
COOKIE = "reads their session cookie"


def proposal(**overrides) -> ModelTriage:
    """A well-evidenced proposal for REPORT; override any top-level field."""
    data = {
        "is_vulnerability_report": True,
        "summary": "Reflected XSS in the search page of ExampleCMS.",
        "affected_product": "ExampleCMS 4.2.0 through 4.2.3",
        "cwe": "CWE-79",
        "cwe_quote": "does not neutralize the q parameter of /search",
        "cvss": {
            "AV": {"value": "N", "quote": NETWORK},
            "AC": {"value": "L", "quote": NETWORK},
            "PR": {"value": "N", "quote": NETWORK},
            "UI": {"value": "R", "quote": LINK},
            "S": {"value": "U", "quote": ""},
            "C": {"value": "H", "quote": COOKIE},
            "I": {"value": "N", "quote": COOKIE},
            "A": {"value": "N", "quote": COOKIE},
        },
        "recommended_next_step": "Reproduce on 4.2.3 and check whether 4.2.4 encodes q.",
        "confidence": "high",
        "evidence_quotes": [{"claim": "affected versions", "quote": "ExampleCMS 4.2.0 through 4.2.3"}],
    }
    data.update(overrides)
    return ModelTriage.model_validate(data)


def guess_all(p: ModelTriage, keep: set[str]) -> ModelTriage:
    """Blank the quote of every CVSS metric not in `keep`."""
    cvss = p.cvss.model_dump()
    for name in cvss:
        if name not in keep:
            cvss[name]["quote"] = ""
    return p.model_copy(update={"cvss": type(p.cvss).model_validate(cvss)})


class FakeOpenAI:
    """Stands in for openai.OpenAI; records calls and returns a fixed parsed response."""

    def __init__(self, parsed: ModelTriage | None):
        self.calls = 0
        self.parsed = parsed
        self.responses = self

    def __call__(self, **client_options):
        return self

    def parse(self, **kwargs):
        self.calls += 1
        return SimpleNamespace(
            output_parsed=self.parsed,
            status="completed" if self.parsed else "incomplete",
            usage=SimpleNamespace(input_tokens=1000, output_tokens=500),
        )


@pytest.fixture
def fake_openai(monkeypatch):
    fake = FakeOpenAI(proposal())
    monkeypatch.setattr("vuln_triage.triage.OpenAI", fake)
    return fake


POOL = [
    {
        "id": "CVE-0000-0001",
        "text": "Reflected cross-site scripting in the search page.",
        "cwe": "CWE-79",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    {
        "id": "CVE-0000-0002",
        "text": "Buffer overflow in the TIFF parser causes a crash.",
        "cwe": "CWE-787",
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
    },
]


@pytest.fixture(autouse=True)
def tiny_pool(monkeypatch):
    """Tests never load the real retrieval pool."""
    monkeypatch.setattr("vuln_triage.retrieval.pool_index", lambda: Index(POOL))
