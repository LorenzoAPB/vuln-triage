"""Build the retrieval pool: NVD-scored CVEs from 2022, before both eval windows (dev and test are 2023).

Same record filter as the eval splits (NVD's own primary CVSS 3.1 vector, specific CWE ids, no SAP),
without the length and per-severity limits. Used for nearest-neighbour examples and CWE priors.

  python -m evals.build_pool    # writes evals/pool.jsonl.gz
"""

import gzip
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from evals.build_dataset import NVD_API

HERE = Path(__file__).parent
MONTHS = [
    (f"2022-{m:02d}-01T00:00:00.000", f"2022-{m:02d}-{d}T23:59:59.999")
    for m, d in zip(range(1, 13), [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31], strict=True)
]


def get(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "vuln-triage-eval-builder"})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            if attempt == 5:
                raise
            print(f"NVD error {e}, retrying")
            time.sleep(15)
    raise AssertionError("unreachable")


def pool_item(vuln: dict) -> dict | None:
    cve = vuln["cve"]
    text = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "").strip()
    vector = next(
        (
            m["cvssData"]["vectorString"]
            for m in cve.get("metrics", {}).get("cvssMetricV31", [])
            if m["source"] == "nvd@nist.gov" and m["type"] == "Primary"
        ),
        None,
    )
    cwes = [d["value"] for w in cve.get("weaknesses", []) if w["source"] == "nvd@nist.gov" for d in w["description"]]
    if not vector or not text or not cwes or not all(c.startswith("CWE-") for c in cwes) or "SAP" in text:
        return None
    return {"id": cve["id"], "text": text, "cwe": cwes[0], "vector": vector}


def main() -> None:
    items: list[dict] = []
    for start, end in MONTHS:
        index, total = 0, 1
        while index < total:
            data = get(f"{NVD_API}?pubStartDate={start}&pubEndDate={end}&resultsPerPage=2000&startIndex={index}")
            total = data["totalResults"]
            items += [i for v in data["vulnerabilities"] if (i := pool_item(v))]
            index += data["resultsPerPage"]
            print(start[:7], index, total, len(items))
            time.sleep(7)  # NVD allows 5 requests per 30 s without an API key
    with gzip.open(HERE / "pool.jsonl.gz", "wt") as f:
        for item in items:
            f.write(json.dumps(item) + "\n")
    print(f"wrote {len(items)} items")


if __name__ == "__main__":
    main()
