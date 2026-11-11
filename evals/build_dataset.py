"""Build an eval split from public NVD records plus hand-written synthetic items.

Selection rule (no hand-picking): for each CVSS v3.1 severity, query NVD API 2.0 for CVEs
published in the split's window, keep records where NVD itself (nvd@nist.gov) assigned the
primary CVSS 3.1 vector and only specific CWE ids, the English description is 150-900
characters and does not mention SAP, then take the first `per_severity` with distinct CWEs
in NVD's result order.

  python -m evals.build_dataset dev    # prompt iteration happens on this split only
  python -m evals.build_dataset test   # held out; overwrites the committed snapshot
"""

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SPLITS = {  # name: [(publication window, items per severity), ...]
    "test": [(("2023-03-01T00:00:00.000", "2023-04-30T23:59:59.999"), 9)],
    "dev": [
        (("2023-06-01T00:00:00.000", "2023-07-31T23:59:59.999"), 3),
        (("2023-09-01T00:00:00.000", "2023-10-31T23:59:59.999"), 6),  # added for v4: a larger dev split
    ],
}
HERE = Path(__file__).parent


def nvd_item(vuln: dict) -> dict | None:
    cve = vuln["cve"]
    text = next(d["value"] for d in cve["descriptions"] if d["lang"] == "en").strip()
    vector = next(
        (
            m["cvssData"]["vectorString"]
            for m in cve.get("metrics", {}).get("cvssMetricV31", [])
            if m["source"] == "nvd@nist.gov" and m["type"] == "Primary"
        ),
        None,
    )
    cwes = [d["value"] for w in cve.get("weaknesses", []) if w["source"] == "nvd@nist.gov" for d in w["description"]]
    if not vector or not cwes or not all(c.startswith("CWE-") for c in cwes):
        return None
    if not 150 <= len(text) <= 900 or "SAP" in text:
        return None
    return {
        "id": cve["id"],
        "kind": "nvd",
        "source": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        "text": text,
        "is_report": True,
        "cwe": cwes[0],
        "cwe_all": cwes,
        "vector": vector,
    }


def fetch(severity: str, window: tuple[str, str]) -> list[dict]:
    url = f"{NVD_API}?cvssV3Severity={severity}&pubStartDate={window[0]}&pubEndDate={window[1]}&resultsPerPage=400"
    request = urllib.request.Request(url, headers={"User-Agent": "vuln-triage-eval-builder"})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)["vulnerabilities"]
        except urllib.error.HTTPError as e:  # NVD returns 503/403 under load or rate limiting
            if attempt == 4:
                raise
            print(f"NVD {e.code}, retrying")
            time.sleep(10)
    raise AssertionError("unreachable")


def pick(window: tuple[str, str], per_severity: int) -> list[dict]:
    from cvss import CVSS3

    items: list[dict] = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        picked: list[dict] = []
        for vuln in fetch(severity, window):
            item = nvd_item(vuln)
            if item and item["cwe"] not in {p["cwe"] for p in picked}:
                item["severity"] = CVSS3(item["vector"]).severities()[0]
                if item["severity"].upper() == severity:
                    picked.append(item)
            if len(picked) == per_severity:
                break
        items += picked
        time.sleep(7)  # NVD allows 5 requests per 30 s without an API key
    return items


def main() -> None:
    split = sys.argv[1]
    items: list[dict] = []
    for window, per_severity in SPLITS[split]:
        items += pick(window, per_severity)

    synthetic = [json.loads(line) for line in (HERE / f"{split}_synthetic.jsonl").read_text().splitlines() if line]
    with (HERE / f"{split}.jsonl").open("w") as f:
        for item in items + synthetic:
            f.write(json.dumps(item) + "\n")
    print(f"wrote {len(items)} NVD + {len(synthetic)} synthetic items to {HERE / f'{split}.jsonl'}")


if __name__ == "__main__":
    main()
