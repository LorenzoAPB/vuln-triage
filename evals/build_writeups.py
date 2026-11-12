"""Build eval splits from public researcher write-ups (Exploit-DB), labeled with NVD's CVSS v3.1 vector and CWE.

Selection rule (no hand-picking):
- Exploit-DB entries whose `codes` name exactly one CVE from 2020-2023 and whose file is prose (.txt or .md).
- NVD (nvd@nist.gov) assigned the primary CVSS 3.1 vector and only specific CWE ids; no SAP anywhere.
- Leakage stripped: CVE ids, CWE ids, CVSS vectors and scores, severity/risk lines, NVD/MITRE links.
- 300+ characters after cleaning; truncated to MAX_CHARS.
- Split by CVE year: dev = CVE-2020/2021, test = CVE-2022/2023 (disjoint CVEs and CVE years).
- Per split and severity, the first N by Exploit-DB id, at most 2 per CWE per severity.
Exploit-DB has almost no single-CVE prose entry that NVD rates Low, so the splits hold Medium, High and Critical.
Each item also keeps NVD's own description (`nvd_text`) for the write-up vs description comparison.

  python -m evals.build_writeups    # writes evals/writeups_dev.jsonl and evals/writeups_test.jsonl
"""

import csv
import gzip
import json
import re
import urllib.request
from collections import Counter
from pathlib import Path

from evals.build_pool import pool_item

HERE = Path(__file__).parent
CACHE = HERE.parent / ".cache"
EDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EDB_RAW = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/"
MAX_CHARS = 6000
PER_SEVERITY = {"dev": 10, "test": 15}
SPLIT_OF_YEAR = {"2020": "dev", "2021": "dev", "2022": "test", "2023": "test"}

SEV = r"\b(critical|high|medium|low)\b(?!\.com)"  # severity words, not medium.com links
LEAK_LINES = [  # a matching line is removed whole
    r"\b(cvss|base score|severity|risk( level| rating)?|cwe)\b",  # explicit scoring vocabulary
    rf"^\W*{SEV}\W*([-:].*)?$",  # a bare rating line such as "High" or "Medium - ..."
    rf"\b(status|rated|rating|priority|impact)\b\W.*{SEV}",  # "Status: CRITICAL", "rated to pose a medium"
    rf"{SEV}\W*(vulnerability|risk|issue|impact|priority)\b",  # "HIGH Vulnerability"
    rf"\b(is|pose[sd]?)\b[^.\n]{{0,20}}{SEV}",  # "this issue is kind of critical"
]
LEAK_LINE = re.compile("(?im)^.*(" + "|".join(LEAK_LINES) + ").*$")
LEAK_TOKEN = [  # links first, so a CVE id inside a link goes with the link
    (re.compile(r"https?://\S*(nvd\.nist\.gov|cve\.mitre\.org|cve\.org|cwe\.mitre\.org)\S*", re.I), "[link removed]"),
    (re.compile(r"CVE-\d{4}-\d{4,}", re.I), "[CVE id removed]"),
    (re.compile(r"CWE-\d+", re.I), "[CWE id removed]"),
]


def clean(text: str) -> str:
    """Remove anything that states the label or points at the NVD record."""
    text = LEAK_LINE.sub("", text)
    for pattern, repl in LEAK_TOKEN:
        text = pattern.sub(repl, text)
    text = re.sub(r"\n{3,}", "\n\n", text.replace("\r", "")).strip()
    return text[:MAX_CHARS]


def nvd_labels() -> dict[str, dict]:
    """NVD records (id, description, CWE, vector) for CVE-2020 to CVE-2023, from NVD's yearly JSON 2.0 feeds."""
    labels: dict[str, dict] = {}
    for year in SPLIT_OF_YEAR:
        path = CACHE / "nvdfeed" / f"nvdcve-2.0-{year}.json.gz"
        if not path.exists():
            fetch(f"{NVD_FEED}nvdcve-2.0-{year}.json.gz", path)
        with gzip.open(path, "rt") as f:
            labels.update((i["id"], i) for v in json.load(f)["vulnerabilities"] if (i := pool_item(v)))
    return labels


def fetch(url: str, path: Path) -> str:
    """Download once into the gitignored cache; later runs read the cached copy."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(url, headers={"User-Agent": "vuln-triage-eval-builder"})
        with urllib.request.urlopen(request, timeout=60) as response:
            path.write_bytes(response.read())
    return path.read_text(errors="replace")


def main() -> None:
    from cvss import CVSS3

    labels = nvd_labels()
    rows = sorted(
        csv.DictReader(fetch(EDB_CSV, CACHE / "edb" / "files_exploits.csv").splitlines()), key=lambda r: int(r["id"])
    )
    picked: dict[str, list[dict]] = {"dev": [], "test": []}
    per_cwe: Counter[tuple[str, str, str]] = Counter()
    seen: set[str] = set()
    for row in rows:
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", row["codes"])))
        if len(cves) != 1 or not row["file"].endswith((".txt", ".md")):
            continue
        cve = cves[0]
        split = SPLIT_OF_YEAR.get(cve[4:8])
        label = labels.get(cve)
        if not split or not label or cve in seen:
            continue
        severity = CVSS3(label["vector"]).severities()[0]
        if sum(i["severity"] == severity for i in picked[split]) >= PER_SEVERITY[split]:
            continue
        if per_cwe[(split, severity, label["cwe"])] >= 2:
            continue
        raw = fetch(EDB_RAW + row["file"], CACHE / "edb" / "raw" / Path(row["file"]).name)
        text = clean(raw)
        if len(text) < 300 or re.search(r"\bSAP\b", raw) or re.search(r"\bSAP\b", label["text"]):
            continue
        seen.add(cve)
        per_cwe[(split, severity, label["cwe"])] += 1
        picked[split].append(
            {
                "id": f"EDB-{row['id']}",
                "kind": "writeup",
                "source": f"https://www.exploit-db.com/exploits/{row['id']}",
                "cve": cve,
                "text": text,
                "nvd_text": label["text"],
                "is_report": True,
                "cwe": label["cwe"],
                "cwe_all": [label["cwe"]],
                "vector": label["vector"],
                "severity": severity,
            }
        )
    for split, items in picked.items():
        synthetic = [json.loads(line) for line in (HERE / f"{split}_synthetic.jsonl").read_text().splitlines() if line]
        with (HERE / f"writeups_{split}.jsonl").open("w") as f:
            f.writelines(json.dumps(i) + "\n" for i in items + synthetic)
        print(split, Counter(i["severity"] for i in items), f"+ {len(synthetic)} synthetic")


if __name__ == "__main__":
    main()
