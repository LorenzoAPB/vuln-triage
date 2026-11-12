import json
from pathlib import Path

from evals.build_writeups import clean
from evals.run import load_split

EVALS = Path(__file__).parent.parent / "evals"


def test_clean_strips_label_leaks():
    raw = (
        "# CVE: CVE-2022-12345\n"
        "# CVSS: 9.8 (AV:N/AC:L)\n"
        "Severity: Critical\n"
        "High\n"
        "Status: CRITICAL\n"
        "This issue is kind of critical, sorry.\n"
        "CWE-89 SQL injection in the id parameter.\n"
        "See https://nvd.nist.gov/vuln/detail/CVE-2022-12345 and https://medium.com/@someone/post\n"
        "The session token has low entropy."
    )
    text = clean(raw)
    for leak in [
        "CVE-2022",
        "CVSS",
        "9.8",
        "Severity",
        "CRITICAL",
        "kind of critical",
        "CWE-89",
        "nvd.nist",
        "\nHigh\n",
    ]:
        assert leak not in text
    assert "medium.com" in text  # a blog link is not a severity
    assert "low entropy" in text  # ordinary prose survives


def test_writeup_splits_are_disjoint_and_labeled():
    dev, test = load_split("writeups-dev"), load_split("writeups-test")
    dev_cves = {i["cve"] for i in dev if i["kind"] == "writeup"}
    test_cves = {i["cve"] for i in test if i["kind"] == "writeup"}
    assert dev_cves and test_cves and not dev_cves & test_cves
    old = {json.loads(line)["id"] for name in ["dev", "test"] for line in (EVALS / f"{name}.jsonl").open()}
    assert not (dev_cves | test_cves) & old
    for item in dev + test:
        if item["kind"] == "writeup":
            assert item["vector"].startswith("CVSS:3.1/") and item["cwe"].startswith("CWE-")
            assert item["cve"] not in item["text"] and "SAP" not in item["text"].split()


def test_nvd_comparison_split_swaps_only_the_text():
    writeups, descriptions = load_split("writeups-test"), load_split("writeups-test-nvd")
    assert [i["id"] for i in writeups] == [i["id"] for i in descriptions]
    for w, d in zip(writeups, descriptions, strict=True):
        assert (w.get("vector"), w.get("cwe")) == (d.get("vector"), d.get("cwe"))
        assert d["text"] == (w["nvd_text"] if w["kind"] == "writeup" else w["text"])
